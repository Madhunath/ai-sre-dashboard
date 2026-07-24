import json
import os
import subprocess
import threading
import time

import boto3
import requests
from flask import Flask, jsonify, redirect, Response, render_template, request, session, url_for

from admin.auth import (
    authenticate_user, bootstrap_admin_db, create_viewer, list_viewers, update_viewer,
    delete_viewer, log_remediation_audit, list_remediation_audits, get_user_allowed_sources
)
from admin.log_assistant import answer_log_question
from admin.reports import available_log_sources, is_log_source_allowed, load_reports, reports_for_sources, service_inventory
from admin.finops import get_aws_billing_data, get_resource_utilization, get_finops_recommendations
from config import (
    ADMIN_SECRET_KEY,
    AWS_REGION,
    DEFAULT_MONITOR_INTERVAL_SECONDS,
    SNS_TOPIC_ARN,
    SRE_COOLDOWN_LOCK_FILE,
    SRE_COOLDOWN_PERIOD_SECONDS,
)

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

app = Flask(
    __name__,
    template_folder=os.path.join(PROJECT_ROOT, "templates"),
    static_folder=os.path.join(PROJECT_ROOT, "static"),
)
app.secret_key = ADMIN_SECRET_KEY

# Stateful lock track file
COOLDOWN_LOCK_FILE = os.getenv(
    "SRE_COOLDOWN_LOCK_FILE",
    SRE_COOLDOWN_LOCK_FILE,
)
COOLDOWN_PERIOD_SECONDS = SRE_COOLDOWN_PERIOD_SECONDS
LOCAL_MONITOR_ENABLED = os.getenv("LOCAL_MONITOR_ENABLED", "true").lower() == "true"
LOCAL_MONITOR_INTERVAL_SECONDS = int(os.getenv("LOCAL_MONITOR_INTERVAL_SECONDS", str(DEFAULT_MONITOR_INTERVAL_SECONDS)))
MONITOR_STATUS_LOCK = threading.Lock()
MONITOR_STATUS = {"last_check_at": None, "next_check_at": None}


def require_admin():
    if not session.get("user"):
        return redirect(url_for("admin_login"))
    return None


def require_platform_admin():
    redirect_response = require_admin()
    if redirect_response:
        return redirect_response
    if session.get("role") != "admin":
        return redirect(url_for("admin_dashboard"))
    return None


@app.route("/")
def index():
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    error = None
    requested_role = request.values.get("role", "")
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        try:
            user = authenticate_user(username, password)
            if user and requested_role in {"admin", "viewer"} and user["role"] != requested_role:
                error = f"This account is not a {requested_role} account."
            elif user:
                session.clear()
                session["user"] = user["username"]
                session["role"] = user["role"]
                session["allowed_sources"] = user["allowed_sources"]
                return redirect(url_for("admin_dashboard"))
            error = "Invalid username or password."
        except Exception as exc:
            error = f"Login failed: {exc}"

    return render_template("login.html", error=error, requested_role=requested_role)


@app.route("/admin/logout", methods=["POST"])
def admin_logout():
    session.clear()
    return redirect(url_for("admin_login"))


@app.route("/admin")
def admin_dashboard():
    redirect_response = require_admin()
    if redirect_response:
        return redirect_response

    is_admin = session.get("role") == "admin"
    reports = load_reports() if is_admin else reports_for_sources(get_user_allowed_sources(session.get("user")))
    
    viewers = []
    sources = []
    if is_admin:
        try:
            viewers = list_viewers()
            sources = available_log_sources()
        except Exception:
            pass

    return render_template(
        "dashboard.html",
        reports=reports,
        admin_user=session.get("user"),
        is_admin=is_admin,
        services=service_inventory(),
        viewers=viewers,
        sources=sources,
    )


@app.route("/admin/users", methods=["GET", "POST"])
def admin_users():
    redirect_response = require_platform_admin()
    if redirect_response:
        return redirect_response
    if request.method == "POST":
        try:
            sources = request.form.getlist("sources")
            wildcards_str = request.form.get("wildcards", "").strip()
            if wildcards_str:
                custom_rules = [r.strip() for r in wildcards_str.split(",") if r.strip()]
                sources.extend(custom_rules)
            create_viewer(request.form.get("username", "").strip(), request.form.get("password", ""), sources)
            return redirect(url_for("admin_dashboard") + "?view=users")
        except Exception as exc:
            import urllib.parse
            return redirect(url_for("admin_dashboard") + f"?view=users&error={urllib.parse.quote(str(exc))}")
    return redirect(url_for("admin_dashboard") + "?view=users")


@app.route("/admin/users/<username>", methods=["POST"])
def admin_user_settings(username):
    redirect_response = require_platform_admin()
    if redirect_response:
        return redirect_response
    sources = request.form.getlist("sources")
    wildcards_str = request.form.get("wildcards", "").strip()
    if wildcards_str:
        custom_rules = [r.strip() for r in wildcards_str.split(",") if r.strip()]
        sources.extend(custom_rules)
    update_viewer(username, sources, request.form.get("is_active") == "on", request.form.get("password", ""))
    return redirect(url_for("admin_dashboard") + "?view=users")



@app.route("/admin/ai-chat", methods=["POST"])
def admin_ai_chat():
    redirect_response = require_admin()
    if redirect_response:
        return jsonify({"error": "Authentication required"}), 401
    payload = request.get_json(silent=True) or {}
    question, filename = str(payload.get("question", "")).strip(), str(payload.get("filename", ""))
    if not question or not filename:
        return jsonify({"error": "A question and log report are required."}), 400

    path = os.path.join("reports", filename)
    if not os.path.exists(path) or not filename.startswith("incident_") or not filename.endswith(".json"):
        return jsonify({"error": "Report not found"}), 404

    from admin.reports import _parse_report
    report = _parse_report(path)
    if not report:
        return jsonify({"error": "Failed to parse report"}), 500

    if session.get("role") != "admin":
        allowed = get_user_allowed_sources(session.get("user"))
        filtered_logs = [
            group for group in report.get("fresh_logs", [])
            if is_log_source_allowed(allowed, group["source"])
        ]
        filtered_disk = [
            group for group in report.get("disk_evidence", [])
            if is_log_source_allowed(allowed, group["source"])
        ]
        if not filtered_logs and not filtered_disk:
            return jsonify({"error": "Forbidden"}), 403
        report["fresh_logs"] = filtered_logs
        report["disk_evidence"] = filtered_disk

    disk_terms = {"disk", "space", "storage", "mount", "directory", "file", "folder"}
    is_disk_question = any(term in question.lower() for term in disk_terms)
    context = report["fresh_logs"] + (report.get("disk_evidence", []) if is_disk_question else [])
    return jsonify({"answer": answer_log_question(question, context)})


@app.route("/admin/reports/<filename>")
def get_report_details(filename):
    redirect_response = require_admin()
    if redirect_response:
        return jsonify({"error": "Unauthorized"}), 401

    path = os.path.join("reports", filename)
    if not os.path.exists(path) or not filename.startswith("incident_") or not filename.endswith(".json"):
        return jsonify({"error": "Report not found"}), 404

    from admin.reports import _parse_report
    parsed = _parse_report(path)
    if not parsed:
        return jsonify({"error": "Failed to parse report"}), 500

    if session.get("role") != "admin":
        allowed = get_user_allowed_sources(session.get("user"))
        filtered_logs = [
            group for group in parsed.get("fresh_logs", [])
            if is_log_source_allowed(allowed, group["source"])
        ]
        filtered_disk = [
            group for group in parsed.get("disk_evidence", [])
            if is_log_source_allowed(allowed, group["source"])
        ]
        if not filtered_logs and not filtered_disk:
            return jsonify({"error": "Forbidden"}), 403
            
        parsed["fresh_logs"] = filtered_logs
        parsed["disk_evidence"] = filtered_disk

    return jsonify(parsed)


@app.route("/admin/monitor-status")
def admin_monitor_status():
    redirect_response = require_admin()
    if redirect_response:
        return redirect_response

    with MONITOR_STATUS_LOCK:
        status = MONITOR_STATUS.copy()
    return jsonify(
        enabled=LOCAL_MONITOR_ENABLED,
        last_check_at=status["last_check_at"],
        next_check_at=status["next_check_at"],
        server_time=time.time(),
    )


@app.route("/admin/finops/billing")
def finops_billing():
    redirect_response = require_admin()
    if redirect_response:
        return jsonify({"error": "Unauthorized"}), 401
    try:
        data = get_aws_billing_data()
        return jsonify(data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/admin/finops/utilization")
def finops_utilization():
    redirect_response = require_admin()
    if redirect_response:
        return jsonify({"error": "Unauthorized"}), 401
    context = request.args.get("context", "default").strip()
    namespace = request.args.get("namespace", "default").strip()
    try:
        data = get_resource_utilization(context, namespace)
        return jsonify({"utilization": data})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/admin/finops/compare")
def finops_compare():
    redirect_response = require_admin()
    if redirect_response:
        return jsonify({"error": "Unauthorized"}), 401
    try:
        billing_data = get_aws_billing_data()
        history = billing_data.get("history", [])
        services = billing_data.get("services", [])
        
        history_desc = "\n".join([f"- {h['month']}: ${h['cost']:.2f}" for h in history])
        services_desc = "\n".join([f"- {s['name']}: ${s['cost']:.2f}" for s in services])
        
        prompt = (
            "You are a Senior Cloud FinOps SRE. Analyze the following AWS billing history and service breakdown:\n\n"
            "Billing History:\n"
            f"{history_desc}\n\n"
            "Current Month Service Breakdown:\n"
            f"{services_desc}\n\n"
            "Provide a concise, highly professional automated comparison of the billing trends. "
            "Identify anomalies (like cost spikes), major drivers, and suggest 1-2 key cost-saving actions. "
            "Return only 3 bullet points with clean markdown. Keep it short and actionable. No greetings, introductions or conversational filler."
        )
        
        from admin.log_assistant import answer_log_question
        analysis = answer_log_question(prompt, [])
        return jsonify({"comparison": analysis.strip()})
    except Exception as e:
        error_msg = str(e)
        if "429" in error_msg or "RESOURCE_EXHAUSTED" in error_msg:
            return jsonify({"comparison": "⚠️ **Gemini API Rate Limit Reached (429):** The free tier quota has been exhausted. Please retry in a few seconds or check your AI Studio plan settings."})
        return jsonify({"comparison": f"⚠️ **AI Analysis Offline:** {error_msg}"})


import shutil

@app.route("/admin/logs/stream")
def stream_logs():
    redirect_response = require_admin()
    if redirect_response:
        return "Unauthorized", 401

    source = request.args.get("source", "").strip()
    if not source:
        return "Source is required", 400

    context = request.args.get("context", "default").strip()
    namespace = request.args.get("namespace", "default").strip()
    pod_name = request.args.get("pod", "").strip()

    # RBAC context verification
    if session.get("role") != "admin":
        allowed = get_user_allowed_sources(session.get("user"))
        rbac_source = source
        if source == "k8s":
            rbac_source = f"k8s:{context}/{namespace}/pods/{pod_name}"
        elif source.startswith("k8s:"):
            # If they requested f"k8s:namespace/pod", normalize it to f"k8s:context/namespace/pods/pod"
            pod_info = source.replace("k8s:", "", 1)
            if "/" in pod_info:
                ns, name = pod_info.split("/", 1)
                rbac_source = f"k8s:{context}/{ns}/pods/{name}"
            else:
                rbac_source = f"k8s:{context}/default/pods/{pod_info}"
        if not is_log_source_allowed(allowed, rbac_source):
            return "Forbidden", 403

    # Build the execution command outside of generate() to resolve scope binding issues
    cmd = []
    if source.startswith("docker:"):
        container_name = source.replace("docker:", "", 1)
        cmd = ["docker", "logs", "-f", "--tail", "100", container_name]
    elif source.startswith("k8s:") or source == "k8s":
        if source.startswith("k8s:"):
            pod_info = source.replace("k8s:", "", 1)
            context = "default"
            if "/" in pod_info:
                namespace, pod_name = pod_info.split("/", 1)
            else:
                namespace, pod_name = "default", pod_info

        cmd = ["kubectl", "logs", "-f", "-n", namespace, pod_name, "--tail", "100"]
        if context != "default":
            cmd.extend(["--context", context])
    else:
        unit_name = source if source.endswith(".service") else f"{source}.service"
        cmd = ["journalctl", "-u", unit_name, "-f", "-n", "100", "--no-pager"]

    def generate():
        process = None
        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
            )

            # Stream logs line by line
            print(f"DEBUG stream_logs: Starting to read process stdout for cmd={cmd}", flush=True)
            while True:
                line = process.stdout.readline()
                if not line:
                    print("DEBUG stream_logs: Reached EOF on process stdout", flush=True)
                    break
                clean_line = line.rstrip('\r\n')
                print(f"DEBUG stream_logs: Read line: {clean_line}", flush=True)
                yield f"data: {clean_line}\n\n"
        except Exception as e:
            print(f"DEBUG stream_logs Exception: {str(e)}", flush=True)
            yield f"data: Error: {str(e)}\n\n"
        finally:
            if process:
                print("DEBUG stream_logs: Terminating subprocess", flush=True)
                process.terminate()
                process.wait()

    headers = {
        "X-Accel-Buffering": "no",
        "Cache-Control": "no-cache",
        "Connection": "keep-alive",
    }
    return Response(generate(), mimetype="text/event-stream", headers=headers)


@app.route("/admin/docker/containers")
def list_docker_containers():
    redirect_response = require_admin()
    if redirect_response:
        return jsonify({"error": "Unauthorized"}), 401

    if shutil.which("docker") is None:
        return jsonify({"containers": [], "error": "Docker CLI not found on host"})

    try:
        result = subprocess.run(
            ["docker", "ps", "-a", "--format", "{{.ID}}\t{{.Names}}\t{{.Image}}\t{{.Status}}"],
            capture_output=True,
            text=True,
            timeout=5
        )
        containers = []
        for line in result.stdout.splitlines():
            parts = line.split("\t")
            if len(parts) >= 4:
                containers.append({
                    "id": parts[0],
                    "name": parts[1],
                    "image": parts[2],
                    "status": parts[3]
                })
        return jsonify({"containers": sorted(containers, key=lambda c: c["name"])})
    except Exception as e:
        return jsonify({"containers": [], "error": str(e)})


@app.route("/admin/docker/images")
def list_docker_images():
    redirect_response = require_admin()
    if redirect_response:
        return jsonify({"error": "Unauthorized"}), 401

    if shutil.which("docker") is None:
        return jsonify({"images": [], "error": "Docker CLI not found on host"})

    try:
        result = subprocess.run(
            ["docker", "images", "--format", "{{.Repository}}\t{{.Tag}}\t{{.ID}}\t{{.Size}}\t{{.CreatedAt}}"],
            capture_output=True,
            text=True,
            timeout=5
        )
        images = []
        for line in result.stdout.splitlines():
            parts = line.split("\t")
            if len(parts) >= 4:
                images.append({
                    "repository": parts[0],
                    "tag": parts[1],
                    "id": parts[2],
                    "size": parts[3],
                    "created": parts[4]
                })
        return jsonify({"images": sorted(images, key=lambda img: img["repository"])})
    except Exception as e:
        return jsonify({"images": [], "error": str(e)})


@app.route("/admin/docker/volumes")
def list_docker_volumes():
    redirect_response = require_admin()
    if redirect_response:
        return jsonify({"error": "Unauthorized"}), 401

    if shutil.which("docker") is None:
        return jsonify({"volumes": [], "error": "Docker CLI not found on host"})

    try:
        result = subprocess.run(
            ["docker", "volume", "ls", "--format", "{{.Name}}\t{{.Driver}}\t{{.Scope}}"],
            capture_output=True,
            text=True,
            timeout=5
        )
        volumes = []
        for line in result.stdout.splitlines():
            parts = line.split("\t")
            if len(parts) >= 2:
                volumes.append({
                    "name": parts[0],
                    "driver": parts[1],
                    "scope": parts[2] if len(parts) > 2 else "local"
                })
        return jsonify({"volumes": sorted(volumes, key=lambda vol: vol["name"])})
    except Exception as e:
        return jsonify({"volumes": [], "error": str(e)})


@app.route("/admin/docker/inspect")
def inspect_docker_resource():
    redirect_response = require_admin()
    if redirect_response:
        return jsonify({"error": "Unauthorized"}), 401

    res_type = request.args.get("type", "container").strip().lower()
    name = request.args.get("name", "").strip()

    if not name:
        return jsonify({"error": "Resource name is required"}), 400

    if shutil.which("docker") is None:
        return jsonify({"inspect": "", "error": "Docker CLI not found on host"})

    if session.get("role") != "admin":
        allowed = get_user_allowed_sources(session.get("user"))
        if not is_log_source_allowed(allowed, f"docker:{name}"):
            return jsonify({"error": "Forbidden"}), 403

    try:
        if res_type == "container":
            cmd = ["docker", "inspect", name]
        elif res_type == "image":
            cmd = ["docker", "image", "inspect", name]
        elif res_type == "volume":
            cmd = ["docker", "volume", "inspect", name]
        else:
            return jsonify({"error": f"Invalid resource type: {res_type}"}), 400

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        return jsonify({"inspect": result.stdout or result.stderr})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/admin/k8s/contexts")
def list_k8s_contexts():
    redirect_response = require_admin()
    if redirect_response:
        return jsonify({"error": "Unauthorized"}), 401

    if shutil.which("kubectl") is None:
        return jsonify({"contexts": [], "error": "Kubectl CLI not found on host"})

    try:
        result = subprocess.run(
            ["kubectl", "config", "get-contexts", "--no-headers", "-o", "name"],
            capture_output=True,
            text=True,
            timeout=5
        )
        contexts = [c.strip() for c in result.stdout.splitlines() if c.strip()]

        curr_result = subprocess.run(
            ["kubectl", "config", "current-context"],
            capture_output=True,
            text=True,
            timeout=5
        )
        current = curr_result.stdout.strip()

        # RBAC Context filtering
        if session.get("role") != "admin":
            allowed = get_user_allowed_sources(session.get("user"))
            filtered = []
            for ctx in contexts:
                has_access = False
                for p in allowed:
                    if p == "*" or p == "*:*" or ctx in p or "*" in p:
                        has_access = True
                        break
                if has_access:
                    filtered.append(ctx)
            contexts = filtered

        return jsonify({"contexts": contexts, "current": current})
    except Exception as e:
        return jsonify({"contexts": [], "error": str(e)})


@app.route("/admin/k8s/namespaces")
def list_k8s_namespaces():
    redirect_response = require_admin()
    if redirect_response:
        return jsonify({"error": "Unauthorized"}), 401

    context = request.args.get("context", "").strip()
    if not context:
        return jsonify({"error": "Context is required"}), 400

    try:
        result = subprocess.run(
            ["kubectl", "get", "namespaces", "--no-headers", "-o", "custom-columns=NAME:.metadata.name", f"--context={context}"],
            capture_output=True,
            text=True,
            timeout=5
        )
        namespaces = [ns.strip() for ns in result.stdout.splitlines() if ns.strip()]

        # RBAC Namespace filtering
        if session.get("role") != "admin":
            allowed = get_user_allowed_sources(session.get("user"))
            filtered = []
            for ns in namespaces:
                # Check if viewer has access to any type/name in this context/namespace
                rbac_source = f"k8s:{context}/{ns}/*/*"
                if is_log_source_allowed(allowed, rbac_source):
                    filtered.append(ns)
            namespaces = filtered

        return jsonify({"namespaces": namespaces})
    except Exception as e:
        return jsonify({"namespaces": [], "error": str(e)})


@app.route("/admin/k8s/resources")
def list_k8s_resources():
    redirect_response = require_admin()
    if redirect_response:
        return jsonify({"error": "Unauthorized"}), 401

    context = request.args.get("context", "").strip()
    namespace = request.args.get("namespace", "").strip()
    res_type = request.args.get("type", "").strip().lower()

    if not context or not namespace or not res_type:
        return jsonify({"error": "Context, namespace, and type are required"}), 400

    try:
        cmd = ["kubectl", "get", res_type, f"--context={context}", "--no-headers"]
        # Cluster-scoped resources shouldn't pass namespace argument
        if res_type not in ["nodes", "namespaces", "events"]:
            cmd.extend(["-n", namespace])
        else:
            # If requesting events, scope it to the namespace (events are namespace-scoped, but nodes/namespaces are not)
            if res_type == "events":
                cmd.extend(["-n", namespace])

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        resources = []
        for line in result.stdout.splitlines():
            parts = line.split()
            if not parts:
                continue

            name = parts[0]
            status = "Unknown"
            age = parts[-1]

            if res_type == "pods":
                status = parts[2] if len(parts) > 2 else "Unknown"
                if len(parts) > 1:
                    status += f" ({parts[1]})"
            elif res_type == "deployments":
                status = f"Ready: {parts[1]}" if len(parts) > 1 else "Active"
            elif res_type == "services":
                status = parts[1] if len(parts) > 1 else "Active"
            elif res_type == "events":
                # events standard format: LAST_SEEN TYPE REASON OBJECT MESSAGE
                if len(parts) >= 4:
                    age = parts[0]
                    status = f"{parts[1]} / {parts[2]}"
                    name = parts[3]
                else:
                    name = parts[0]
                    status = "Event"
            elif res_type == "nodes":
                status = parts[1] if len(parts) > 1 else "Active"
            else:
                status = parts[1] if len(parts) > 1 else "Active"

            resources.append({
                "name": name,
                "status": status,
                "age": age
            })
        # RBAC Resource-level list filtering
        if session.get("role") != "admin":
            allowed = get_user_allowed_sources(session.get("user"))
            filtered = []
            for r in resources:
                rbac_source = f"k8s:{context}/{namespace}/{res_type}/{r['name']}"
                if is_log_source_allowed(allowed, rbac_source):
                    filtered.append(r)
            resources = filtered

        return jsonify({"resources": resources})
    except Exception as e:
        return jsonify({"resources": [], "error": str(e)})


@app.route("/admin/k8s/describe")
def describe_k8s_resource():
    redirect_response = require_admin()
    if redirect_response:
        return jsonify({"error": "Unauthorized"}), 401

    context = request.args.get("context", "").strip()
    namespace = request.args.get("namespace", "").strip()
    res_type = request.args.get("type", "").strip().lower()
    name = request.args.get("name", "").strip()

    if not context or not namespace or not res_type or not name:
        return jsonify({"error": "Context, namespace, type, and name are required"}), 400

    if session.get("role") != "admin":
        allowed = get_user_allowed_sources(session.get("user"))
        rbac_source = f"k8s:{context}/{namespace}/{res_type}/{name}"
        if not is_log_source_allowed(allowed, rbac_source):
            return jsonify({"error": "Forbidden: You are not authorized to describe this resource."}), 403

    try:
        cmd = ["kubectl", "describe", f"{res_type}/{name}", "-n", namespace, f"--context={context}"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=8)
        return jsonify({"describe": result.stdout or result.stderr})
    except Exception as e:
        return jsonify({"error": str(e)})


@app.route("/admin/ai/health-brief")
def ai_health_brief():
    redirect_response = require_admin()
    if redirect_response:
        return jsonify({"error": "Unauthorized"}), 401

    is_admin = session.get("role") == "admin"
    reports = load_reports() if is_admin else []
    services = service_inventory()
    
    snapshot = {
        "monitored_services": [{"name": s["name"], "status": s["status"]} for s in services],
        "recent_incidents": [{"summary": r.get("summary", ""), "status": r.get("remediation_status", "")} for r in reports[:3]]
    }
    
    prompt = (
        "You are a Senior DevOps SRE. Provide a concise, highly professional 2-sentence executive summary of the cluster health "
        "based on the following snapshot. Highlight any active failures, anomalies, or outstanding incidents, and suggest a high-priority action if necessary. "
        "Do not include any greeting or conversational filler. Return just the briefing text.\n\n"
        f"Snapshot Context: {json.dumps(snapshot)}"
    )
    
    try:
        from admin.log_assistant import answer_log_question
        briefing = answer_log_question(prompt, [])
        return jsonify({"briefing": briefing.strip()})
    except Exception as e:
        return jsonify({"briefing": f"AI Health briefing unavailable: {str(e)}"})


@app.route("/admin/ai/analyze-resource", methods=["POST"])
def ai_analyze_resource():
    redirect_response = require_admin()
    if redirect_response:
        return jsonify({"error": "Unauthorized"}), 401
        
    payload = request.get_json(silent=True) or {}
    res_name = payload.get("name", "")
    res_type = payload.get("type", "")
    content = payload.get("content", "")
    platform = payload.get("platform", "k8s").lower().strip()
    
    if not res_name or not content:
        return jsonify({"error": "Resource name and content are required"}), 400
        
    platform_desc = "Docker container hosting environment (propose ONLY raw docker CLI commands for suggested_command and remediation, e.g. docker logs, docker inspect, docker restart)" if platform == "docker" else "Kubernetes hosting environment (propose ONLY kubectl commands, e.g. kubectl describe, kubectl logs, kubectl rollout)"
    
    prompt = (
        "You are an expert Kubernetes and Docker SRE troubleshooter. "
        f"Analyze the following telemetry content for the resource '{res_type}/{res_name}' running in a {platform_desc}. "
        "The content can be either application log streams OR kubectl/docker describe metadata. "
        "If it is describe metadata (common for ingresses, deployments, services, events, nodes, or docker inspect), "
        "inspect the configuration, rules, backend paths, endpoints, status states, and active events "
        "for misconfigurations, mismatching targets, or warnings. Do not report that logs are missing or empty "
        "if the resource type naturally does not produce application logs.\n"
        "Return your response in a clear, JSON structure (do not include markdown block quotes like ```json, just raw JSON) containing exactly these keys:\n"
        "1. 'analysis': A concise 2-sentence summary of the findings.\n"
        "2. 'proposed_fix': Markdown bullet list explaining how to fix it.\n"
        "3. 'risk_level': Low, Medium, or High.\n"
        "4. 'suggested_command': A single CLI command that can resolve or inspect the issue.\n\n"
        f"Content:\n{content[:4000]}"
    )
    
    try:
        from admin.log_assistant import answer_log_question
        raw_answer = answer_log_question(prompt, [])
        
        clean_str = raw_answer.strip()
        if clean_str.startswith("```json"):
            clean_str = clean_str.replace("```json", "", 1)
        if clean_str.endswith("```"):
            clean_str = clean_str[:-3]
        clean_str = clean_str.strip()
        
        parsed_data = json.loads(clean_str)
        return jsonify(parsed_data)
    except Exception as e:
        return jsonify({
            "analysis": "Gemini analyzed the telemetry, but formatting could not be parsed.",
            "proposed_fix": raw_answer if len(raw_answer) > 10 else f"Check logs for anomalies. Error: {str(e)}",
            "risk_level": "Medium",
        })


@app.route("/admin/ai/explorer-chat", methods=["POST"])
def admin_explorer_chat():
    redirect_response = require_admin()
    if redirect_response:
        return jsonify({"error": "Unauthorized"}), 401

    payload = request.get_json(silent=True) or {}
    question = str(payload.get("question", "")).strip()
    res_name = str(payload.get("name", "")).strip()
    res_type = str(payload.get("type", "")).strip()
    platform = str(payload.get("platform", "k8s")).strip().lower()
    content = str(payload.get("content", "")).strip()
    history = payload.get("history", [])

    if not question or not res_name or not content:
        return jsonify({"error": "Question, resource name, and context content are required"}), 400

    platform_desc = "Docker container environment" if platform == "docker" else "Kubernetes environment"

    history_str = ""
    for msg in history[-8:]:
        role = "User" if msg["sender"] == "user" else "Assistant"
        history_str += f"{role}: {msg['text']}\n"

    prompt = (
        "You are an expert DevOps SRE AI assistant. You are helping a developer inspect a live resource "
        f"named '{res_type}/{res_name}' running in a {platform_desc}.\n\n"
        "Here is the active logs or describe configuration telemetry of the resource:\n"
        "-------------------\n"
        f"{content[:5000]}\n"
        "-------------------\n\n"
        "Instructions:\n"
        "1. Answer the user's questions directly if they are asking for log analysis or troubleshooting insights.\n"
        "2. If the user asks you to perform an action (e.g. start, stop, restart, scale, run, delete, downscale), "
        "translate their request into a single whitelisted CLI command. The ONLY allowed commands you may suggest are:\n"
        "   - docker start/stop/restart <container-name>\n"
        "   - docker rm [-f] <container-name>\n"
        "   - docker run -d --name <container-name> [-e <env>=<val>] -p <host-port>:<container-port> <image-name>\n"
        "   - kubectl scale deployment/statefulset <deployment-name> --replicas=<num> [-n <namespace>]\n"
        "   - kubectl rollout restart deployment/<deployment-name> [-n <namespace>]\n"
        "   - aws ec2 delete-volume --volume-id vol-<id> [--region <region-name>]\n"
        "   - aws ec2 stop-instances --instance-ids i-<id> [--region <region-name>]\n"
        "3. If suggesting a command, output it clearly on its own line so the system's regex can detect it and render a run button.\n\n"
        "Conversation History:\n"
        f"{history_str}"
        f"User: {question}\n"
        "Assistant:"
    )

    try:
        from admin.log_assistant import answer_log_question
        answer = answer_log_question(prompt, [])
        return jsonify({"answer": answer.strip()})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/admin/remediation/execute", methods=["POST"])
def execute_remediation_command():
    redirect_response = require_admin()
    if redirect_response:
        return jsonify({"error": "Unauthorized"}), 401
        
    if session.get("role") != "admin":
        return jsonify({"error": "Forbidden: Only administrators can execute remediations."}), 403
        
    payload = request.get_json(silent=True) or {}
    command = str(payload.get("command", "")).strip()
    
    if not command:
        return jsonify({"error": "Command is required"}), 400
        
    import re
    pattern = (
        r"^("
        r"((docker|systemctl|sudo\s+systemctl)\s+(start|restart|stop)\s+[a-zA-Z0-9_./-]+)|"
        r"((docker)\s+(rm|rmi|image\s+rm|volume\s+rm)\s+(-f\s+)?[a-zA-Z0-9_./:-]+)|"
        r"(kubectl\s+scale\s+(deployment|statefulset)\s+[a-zA-Z0-9_./-]+\s+--replicas=[0-9]+(\s+-n\s+[a-zA-Z0-9_.-]+)?(\s+--context=[a-zA-Z0-9_.:/-]+)?)|"
        r"(kubectl\s+rollout\s+restart\s+(deployment|statefulset|daemonset|deployment.apps|statefulset.apps)(/|\s+)[a-zA-Z0-9_./-]+(\s+-n\s+[a-zA-Z0-9_.-]+)?(\s+--context=[a-zA-Z0-9_.:/-]+)?)|"
        r"(aws\s+ec2\s+delete-volume\s+--volume-id\s+vol-[a-f0-9]+(\s+--region\s+[a-z0-9-]+)?)|"
        r"(aws\s+ec2\s+stop-instances\s+--instance-ids\s+i-[a-f0-9]+(\s+--region\s+[a-z0-9-]+)?)|"
        r"(docker\s+run\s+-d\s+--name\s+[a-zA-Z0-9_./-]+\s+(-e\s+[a-zA-Z0-9_.-]+=[a-zA-Z0-9_.-]+\s+)?-p\s+[0-9]+:[0-9]+\s+[a-zA-Z0-9_./:-]+)"
        r")$"
    )
    if not re.match(pattern, command):
        return jsonify({
            "error": "Security validation failed. Only start/restart/stop/remove on containers/services/images/volumes, kubectl deployment scaling and rollout restart, volume deletions, EC2 stop instance operations, and standard docker run commands are permitted."
        }), 400
        
    operator = session.get("user", "unknown-admin")
    
    try:
        cmd_parts = command.split()
        
        # Check if this is an AWS EC2 command and has no --region parameter
        is_aws_ec2_cmd = ("aws" in cmd_parts and "ec2" in cmd_parts and ("stop-instances" in cmd_parts or "delete-volume" in cmd_parts))
        has_region_flag = "--region" in cmd_parts
        
        if is_aws_ec2_cmd and not has_region_flag:
            target_id = None
            for i, part in enumerate(cmd_parts):
                if part == "--instance-ids" or part == "--volume-id":
                    if i + 1 < len(cmd_parts):
                        target_id = cmd_parts[i + 1]
                        break
            
            if target_id:
                regions_to_check = ['us-east-1', 'us-east-2', 'us-west-1', 'us-west-2', 'eu-west-1', 'ap-south-1', 'ap-southeast-1', 'sa-east-1']
                found_region = None
                
                try:
                    from config import AWS_REGION
                    ec2_meta = boto3.client('ec2', region_name=AWS_REGION)
                    reg_resp = ec2_meta.describe_regions()
                    regions_to_check = [r['RegionName'] for r in reg_resp.get('Regions', [])]
                except Exception:
                    pass
                
                for region in regions_to_check:
                    try:
                        if "stop-instances" in cmd_parts:
                            chk_client = boto3.client('ec2', region_name=region)
                            chk_client.describe_instances(InstanceIds=[target_id])
                            found_region = region
                            break
                        elif "delete-volume" in cmd_parts:
                            chk_client = boto3.client('ec2', region_name=region)
                            chk_client.describe_volumes(VolumeIds=[target_id])
                            found_region = region
                            break
                    except Exception:
                        continue
                
                if found_region:
                    cmd_parts.extend(["--region", found_region])
                    command = " ".join(cmd_parts)
                    print(f"DEBUG: Auto-discovered target region '{found_region}' for resource '{target_id}'", flush=True)

        result = subprocess.run(cmd_parts, capture_output=True, text=True, timeout=12)
        
        stdout = result.stdout
        stderr = result.stderr
        success = (result.returncode == 0)
        
        # Reassure user on empty success output
        if success and not stdout.strip() and not stderr.strip():
            if "systemctl" in cmd_parts:
                action = next((x for x in ["start", "stop", "restart"] if x in cmd_parts), "execute")
                service = cmd_parts[-1]
                stdout = f"Service '{service}' successfully {action}ed.\n"
            elif "docker" in cmd_parts:
                action = next((x for x in ["start", "stop", "restart", "rm", "run"] if x in cmd_parts), "execute")
                container = cmd_parts[-1]
                if action == "rm":
                    stdout = f"Container '{container}' successfully removed.\n"
                else:
                    stdout = f"Container '{container}' successfully {action}ed.\n"
            else:
                stdout = "Command completed successfully with no output.\n"
                
        log_remediation_audit(
            operator=operator,
            command=command,
            exit_code=result.returncode,
            stdout=stdout,
            stderr=stderr,
            success=success
        )
        
        return jsonify({
            "command": command,
            "stdout": stdout,
            "stderr": stderr,
            "exit_code": result.returncode,
            "success": success
        })
    except Exception as e:
        log_remediation_audit(
            operator=operator,
            command=command,
            exit_code=-1,
            stdout="",
            stderr=str(e),
            success=False
        )
        return jsonify({"error": f"Failed to execute command: {str(e)}"}), 500


@app.route("/admin/remediation/audits", methods=["GET"])
def get_remediation_audits():
    redirect_response = require_admin()
    if redirect_response:
        return jsonify({"error": "Unauthorized"}), 401
        
    if session.get("role") != "admin":
        return jsonify({"error": "Forbidden"}), 403
        
    try:
        audits = list_remediation_audits()
        return jsonify({"audits": audits})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/admin/users/delete", methods=["POST"])
def delete_viewer_user():
    redirect_response = require_admin()
    if redirect_response:
        return jsonify({"error": "Unauthorized"}), 401
        
    if session.get("role") != "admin":
        return jsonify({"error": "Forbidden"}), 403
        
    payload = request.get_json(silent=True) or {}
    username = str(payload.get("username", "")).strip()
    
    if not username:
        return jsonify({"error": "Username is required"}), 400
        
    try:
        delete_viewer(username)
        return jsonify({"status": "success", "message": f"User {username} deleted successfully."})
    except Exception as e:
        return jsonify({"error": str(e)}), 500





def trigger_sre_agent(ignore_cooldown=False):
    from main import run_sre_loop
    
    # ⏱️ 1. Check if we already handled an incident recently
    if not ignore_cooldown and os.path.exists(COOLDOWN_LOCK_FILE):
        with open(COOLDOWN_LOCK_FILE, "r") as f:
            try:
                last_run = float(f.read().strip())
                elapsed = time.time() - last_run
                if elapsed < COOLDOWN_PERIOD_SECONDS:
                    remaining = int(COOLDOWN_PERIOD_SECONDS - elapsed)
                    print(f"🛑 [COOLDOWN ACTIVE] Active lock found. Ignoring duplicate cloud burst alerts for another {remaining}s.")
                    return False
            except ValueError:
                pass 

    # 🔑 2. Lock the engine so concurrent alerts hit a brick wall
    with open(COOLDOWN_LOCK_FILE, "w") as f:
        f.write(str(time.time()))
        
    run_sre_loop()
    return True

@app.route('/sns-webhook', methods=['POST'])
def handle_sns_notification():
    try:
        data = json.loads(request.data.decode('utf-8'))
    except Exception:
        return jsonify({"status": "error", "message": "Invalid JSON payload"}), 400

    # Handle AWS SNS Subscription Confirmation Setup
    if data.get("Type") == "SubscriptionConfirmation":
        subscribe_url = data.get("SubscribeURL")
        print(f"\n🔗 [AWS SNS] Confirming subscription route via: {subscribe_url}")
        requests.get(subscribe_url)
        return jsonify({"status": "confirmed"}), 200

    # Handle Incoming Incidents
    if data.get("Type") == "Notification":
        message_json = data.get("Message", "")
        
        try:
            msg_details = json.loads(message_json)
            new_state = msg_details.get("NewStateValue")
            
            # 🟢 Case A: The server cleared up and CloudWatch officially says OK
            if new_state == "OK":
                print("ℹ️ [AWS ALARM] System state returned to OK. Clearing agent cooldown lock.")
                if os.path.exists(COOLDOWN_LOCK_FILE):
                    os.remove(COOLDOWN_LOCK_FILE) # Lift lock instantly!
                return jsonify({"status": "lock_cleared"}), 200
                
            # 🔴 Case B: It's an active ALARM state execution
            elif new_state == "ALARM":
                print("\n🚨 [AWS ALARM TRIGGERED] Sensed incoming SNS alert. Evaluating pipeline locks...")
                was_triggered = trigger_sre_agent()
                
                if not was_triggered:
                    return jsonify({"status": "skipped_due_to_cooldown"}), 200
                    
                return jsonify({"status": "processed"}), 200
                
            else:
                print(f"ℹ️ [AWS SNS] Received other notification state: {new_state}. Ignoring.")
                return jsonify({"status": "ignored"}), 200
                
        except Exception:
            print("ℹ️ [AWS SNS] Non-JSON or non-alarm message received. Ignoring to prevent loop.")
            return jsonify({"status": "ignored_non_alarm"}), 200

    return jsonify({"status": "ignored"}), 200

def publish_ai_report_to_sns(analysis_result, execution_result, notification_type: str = "incident"):
    if not SNS_TOPIC_ARN:
        print("SNS_TOPIC_ARN is not configured. Skipping SNS notification.")
        return

    sns_client = boto3.client('sns', region_name=AWS_REGION)
    topic_arn = SNS_TOPIC_ARN
    is_recovery = notification_type == "recovery"
    subject = (
        "✅ AI SRE Recovery Confirmed"
        if is_recovery
        else f"🤖 AI SRE Incident Detected: {execution_result.get('status').upper()}"
    )
    
    report_body = f"""
================= AI SRE AUTOMATED INCIDENT REPORT =================

[{"✅ RECOVERY SUMMARY" if is_recovery else "🚨 INCIDENT SUMMARY"}]
{analysis_result.get('summary')}

[🔍 ROOT CAUSE IDENTIFIED]
{analysis_result.get('root_cause')}

[⚡ ACTION TAKEN]
Recommended Action : {analysis_result.get('recommended_action')} -> Target: ({analysis_result.get('action_target')})
Remediation Result : {execution_result.get('status')} -> {execution_result.get('message')}

=====================================================================
"""
    try:
        print("[🛰️ AWS SNS] Dispatching finished AI report trace back to SNS Topic...")
        sns_client.publish(TopicArn=topic_arn, Message=report_body, Subject=subject)
        print("✅ AI SRE Report published successfully via AWS SNS Native Relay!")
    except Exception as e:
        print(f"❌ Failed to publish back to SNS: {e}")

@app.route("/admin/metrics/history")
def metrics_history():
    import glob
    from datetime import datetime
    redirect_response = require_admin()
    if redirect_response:
        return jsonify({"error": "Unauthorized"}), 401

    time_range = request.args.get("range", "1h").strip().lower()
    now = time.time()
    
    if time_range == "10m":
        cutoff = now - 600
    elif time_range == "30m":
        cutoff = now - 1800
    elif time_range == "1h":
        cutoff = now - 3600
    elif time_range == "6h":
        cutoff = now - 21600
    elif time_range == "custom":
        try:
            hours = float(request.args.get("hours", 12))
            cutoff = now - (hours * 3600)
        except Exception:
            cutoff = now - 43200
    else:
        cutoff = now - 3600
        
    history = []
    
    for path in glob.glob(os.path.join("reports", "incident_*.json")):
        try:
            filename = os.path.basename(path)
            ts_str = filename.replace("incident_", "").replace(".json", "")
            ts = float(ts_str)
            
            if ts >= cutoff:
                with open(path, "r", encoding="utf-8") as f:
                    report = json.load(f)
                    
                evidence = report.get("evidence_snapshot", {})
                cpu_pct = evidence.get("cpu", {}).get("utilization_pct", 0.0)
                mem_pct = evidence.get("memory", {}).get("virtual", {}).get("pct_used", 0.0)
                
                disk_pct = 0.0
                partitions = evidence.get("disk", {}).get("partitions", [])
                for p in partitions:
                    if p.get("mountpoint") == "/":
                        disk_pct = p.get("pct_used", 0.0)
                        break
                        
                history.append({
                    "timestamp": ts,
                    "time_str": datetime.fromtimestamp(ts).strftime("%H:%M:%S" if time_range != "1d" else "%m-%d %H:%M"),
                    "cpu": cpu_pct,
                    "memory": mem_pct,
                    "disk": disk_pct
                })
        except Exception:
            pass
            
    history = sorted(history, key=lambda x: x["timestamp"])
    
    max_points = 50
    if len(history) > max_points:
        step = len(history) // max_points
        if step == 0:
            step = 1
        history = history[::step][:max_points]
        
    return jsonify({"history": history})

@app.route("/admin/ai/log-anomaly-scan", methods=["POST"])
def ai_log_anomaly_scan():
    redirect_response = require_admin()
    if redirect_response:
        return jsonify({"error": "Unauthorized"}), 401
        
    payload = request.get_json(silent=True) or {}
    logs = payload.get("logs", [])
    if not logs:
        return jsonify({"error": "Logs are required"}), 400
        
    from admin.ai_features import generate_log_anomaly_report
    report = generate_log_anomaly_report(logs)
    return jsonify({"report": report})

@app.route("/admin/ai/post-mortem", methods=["POST"])
def ai_post_mortem_gen():
    redirect_response = require_admin()
    if redirect_response:
        return jsonify({"error": "Unauthorized"}), 401
        
    payload = request.get_json(silent=True) or {}
    report_filename = payload.get("filename", "")
    if not report_filename:
        return jsonify({"error": "Report filename is required"}), 400
        
    try:
        report_path = os.path.join("reports", report_filename)
        if not os.path.exists(report_path):
            return jsonify({"error": "Report not found"}), 404
            
        with open(report_path, "r", encoding="utf-8") as f:
            incident_data = json.load(f)
            
        from admin.ai_features import generate_post_mortem
        report = generate_post_mortem(incident_data)
        return jsonify({"post_mortem": report})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/admin/ai/command-copilot", methods=["POST"])
def ai_command_copilot():
    redirect_response = require_admin()
    if redirect_response:
        return jsonify({"error": "Unauthorized"}), 401
        
    payload = request.get_json(silent=True) or {}
    query = payload.get("query", "").strip()
    context = payload.get("context", "default").strip()
    
    if not query:
        return jsonify({"error": "Query is required"}), 400
        
    from admin.ai_features import translate_text_to_cli
    result = translate_text_to_cli(query, context)
    return jsonify(result)

def start_local_monitor(interval_seconds: int = LOCAL_MONITOR_INTERVAL_SECONDS):
    if not LOCAL_MONITOR_ENABLED:
        return None

    def record_check_started():
        with MONITOR_STATUS_LOCK:
            MONITOR_STATUS["last_check_at"] = time.time()
            MONITOR_STATUS["next_check_at"] = None

    def schedule_next_check():
        with MONITOR_STATUS_LOCK:
            MONITOR_STATUS["next_check_at"] = time.time() + interval_seconds

    def _loop():
        print(f"🧭 Local monitoring loop enabled. First check will run immediately and then every {interval_seconds} seconds.")
        record_check_started()
        try:
            trigger_sre_agent(ignore_cooldown=True)
        except Exception as exc:
            print(f"❌ Initial local monitoring run failed: {exc}")

        while True:
            schedule_next_check()
            time.sleep(interval_seconds)
            record_check_started()
            try:
                trigger_sre_agent(ignore_cooldown=True)
            except Exception as exc:
                print(f"❌ Local monitoring tick failed: {exc}")

    thread = threading.Thread(target=_loop, daemon=True, name="local-monitor")
    thread.start()
    return thread


def start_receiver():
    print("🛰️ AI SRE Listener online. Waiting for local monitoring and AWS SNS alerts on port 5000...")
    admin_created = bootstrap_admin_db()
    if admin_created:
        print("Admin database initialized and configured administrator created.")
    else:
        print("Admin database and configured administrator verified.")
    start_local_monitor()
    app.run(host='0.0.0.0', port=5000, use_reloader=False)
