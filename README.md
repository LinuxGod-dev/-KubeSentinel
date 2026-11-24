# KubeSentinel

**Kubernetes security posture scanner with RBAC escalation-path analysis and linked Falco runtime detections.**

Most K8s scanners hand you a flat list of misconfigurations. KubeSentinel does three extra things:

1. **Escalation paths.** It builds a graph of who can become whom (create a pod as another ServiceAccount, exec into a pod and use its token, read token Secrets, impersonate, `bind`/`escalate`, `nodes/proxy`) and reports the *shortest chain* from every non-system identity to **cluster-admin**, **all Secrets**, or **node compromise**. Like [cloud-privesc-finder](https://github.com/LinuxGod-dev/cloud-privesc-finder), but for Kubernetes.
2. **Detection linkage.** Every posture finding names the Falco rule that would catch someone *exploiting* it. `kubesentinel rules` prints the mapping, and tests enforce it.
3. **Prove it.** A lab cluster, an attack manifest and per-rule trigger commands let you demonstrate offense → finding → alert end to end.

```
 manifests / live cluster ──► Inventory ──► checks: workload · rbac · secrets · network/PSA
 (kubectl, read-only)                 └──► RBAC graph ──► BFS ──► escalation paths
                                                  │
                    console · JSON · SARIF (GitHub Security tab) · HTML · Mermaid graph
                                                  │
        finding ──links to──► rules/falco/kubesentinel_rules.yaml (11 runtime rules, ATT&CK-tagged)
```

## What it checks

| Area | Examples |
|---|---|
| Workloads (`KS-WL`) | privileged, hostPID/IPC/network, hostPath + container-runtime sockets, dangerous capabilities, root, privilege escalation, writable rootfs, limits, unpinned images, default SA token, seccomp |
| RBAC (`KS-RBAC`) | cluster-admin grants, wildcards, `escalate`/`bind`/`impersonate`, secrets read, `pods/exec`, workload creation, `nodes/proxy`, token minting, default-SA and broad-group bindings |
| Secrets (`KS-SEC`) | literal credentials in env vars, credentials in ConfigMaps, Secret objects committed to manifests (values are always masked in output) |
| Network / admission | no NetworkPolicy, no default-deny, Pod Security Admission not enforced |
| Escalation (`KS-ESC`) | shortest RBAC chain to cluster-admin / all secrets / node compromise |

Run `kubesentinel rules` for the full catalog with MITRE ATT&CK IDs and linked Falco rules.

---

# Step-by-step: run it locally

Work through the phases in order. **Every step ends with what you should see**, so you can confirm before moving on. If something differs, stop and fix it before continuing.

| Phase | Needs | What you get |
|---|---|---|
| **A. Scanner on manifests** | Python 3.9+ only | the whole scanner, no cluster |
| **B. Lab cluster + live scan** | + Docker, kind, kubectl | scan a real cluster, prove an escalation path |
| **C. Falco runtime rules** | + Helm | alerts firing for the attacks |

Commands are shown for **bash** (Linux/macOS/WSL) and **PowerShell** (Windows) where they differ.

## Phase A: scanner only (no cluster)

**A1. Check Python.**
```
python --version        # Windows: py --version
```
You should see `Python 3.9` or newer.

**A2. Create and activate a virtual environment** (from the project folder).
```bash
# bash
python3 -m venv .venv && source .venv/bin/activate
```
```powershell
# PowerShell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
```
If PowerShell blocks the script: `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`, then activate again.
You should see `(.venv)` at the start of your prompt.

**A3. Install.**
```
pip install -e ".[dev]"
```
You should see `Successfully installed ... kubesentinel-0.1.0 ...`.

**A4. Confirm the tool runs.**
```
kubesentinel --version
```
You should see `kubesentinel 0.1.0`. (If the command isn't found, use `python -m kubesentinel --version`.)

**A5. Run the tests.**
```
pytest -q
```
You should see `53 passed`.

**A6. Scan the hardened baseline.**
```
kubesentinel scan labs/baseline
```
You should see a summary of all zeros and an empty findings table.

**A7. Scan the deliberately vulnerable lab.**
```
kubesentinel scan labs/vulnerable
```
You should see roughly 10 CRITICAL / 16 HIGH findings, then a tree under **RBAC escalation paths**. Find this chain (the headline result):
`ServiceAccount dev/support-bot → exec into a pod in 'ops' → ops/backup → dev/tiller → CLUSTER-ADMIN` (3 hops).

**A8. See details, evidence and the linked Falco rules.**
```
kubesentinel scan labs/vulnerable --verbose --min-severity high
```
Each finding now shows evidence, a fix, and `runtime detection: <Falco rule names>`.

**A9. Produce the reports.**
```
kubesentinel scan labs/vulnerable --min-severity critical --html reports/report.html --json reports/report.json --sarif reports/report.sarif --mermaid reports/paths.mmd
```
You should see the normal console output followed by four `wrote ...` lines. Open `reports/report.html` in a browser (it follows your light/dark setting). Paste the contents of `reports/paths.mmd` into <https://mermaid.live> to see the escalation graph.

**A10. Try the CI gate.**
```bash
kubesentinel scan labs/vulnerable --quiet --fail-on high; echo "exit code: $?"     # bash
```
```powershell
kubesentinel scan labs/vulnerable --quiet --fail-on high; "exit code: $LASTEXITCODE"
```
You should see `exit code: 1`. The same command on `labs/baseline` gives `0`.

Phase A is a complete, working project. Phases B and C add a real cluster and runtime detection.

## Phase B: lab cluster and live scan

**B1. Install the tools** (skip any you have). Docker Desktop (Windows: WSL2 backend) must be *running*.
```powershell
# Windows
winget install Kubernetes.kind Kubernetes.kubectl Helm.Helm
```
```bash
# macOS
brew install kind kubectl helm
# Linux: see https://kind.sigs.k8s.io/docs/user/quick-start/#installation
```
Open a **new** terminal, then check:
```
docker version && kind version && kubectl version --client && helm version
```
All four should print versions (Docker needs both Client and Server sections).

**B2. Create the cluster.**
```
kind create cluster --config labs/kind-config.yaml
```
You should see `Set kubectl context to "kind-kubesentinel"`.

**B3. Confirm the nodes.**
```
kubectl get nodes
```
You should see 2 nodes, both `Ready` (may take ~1 minute).

**B4. Deploy the vulnerable lab.**
```
kubectl apply -f labs/vulnerable/
```
You should see namespaces, service accounts, roles, bindings, pods and deployments `created`. The `Secret` and ConfigMap are included on purpose.

**B5. Wait for the pods.**
```
kubectl get pods -A
```
In `dev` and `ops` you should see `attacker-pod`, `payments-api` and `backup-agent` reach `Running`. (First pull takes a minute.)

**B6. Run the live scan.**
```
kubesentinel scan --live --exclude-namespace kube-system --min-severity high
```
You should see the same classes of findings as Phase A, now read from the cluster (`live cluster` in the header). Note the line saying Secret objects are not read: live mode never fetches Secrets, by design.

**B7. Prove the headline finding is real.** First ask the API server what `ci-runner` can do:
```
kubectl auth can-i create pods -n dev --as=system:serviceaccount:dev:ci-runner
kubectl auth can-i "*" "*" --as=system:serviceaccount:dev:ci-runner
```
You should see `yes` then `no`. It is *not* admin, yet the scanner says it reaches cluster-admin in 2 hops. Now exploit the path, creating a pod **as ci-runner** that runs as `tiller`:
```
kubectl create -f labs/attacks/steal-tiller.yaml --as=system:serviceaccount:dev:ci-runner
```
You should see `pod/steal-tiller created`. Wait a few seconds, then:
```
kubectl logs -n dev steal-tiller
```
You should see `ACCESS GRANTED - first bytes of the response:` followed by `{"kind":"SecretList"...`. A non-admin identity just read `kube-system` Secrets. That is the finding, proven.

**B8. Fix it and re-scan** (optional, to see the scanner react). Enforce Pod Security on `dev` and re-run:
```
kubectl label namespace dev pod-security.kubernetes.io/enforce=baseline --overwrite
kubesentinel scan --live --exclude-namespace kube-system --min-severity high
```
The `NODE COMPROMISE` paths through `dev` should disappear, and `KS-ADM-001` for `dev` goes away. (The tiller chain remains: PSA doesn't fix RBAC. Remove the cluster-admin binding for that.)

## Phase C: Falco runtime detections

> Falco needs kernel access. This works best on a native Linux host or Linux VM. On Docker Desktop/WSL2 it may work with the modern eBPF driver, but if the Falco pod crash-loops, read `kubectl logs -n falco <pod>` for a driver error. Phases A and B do not depend on it.

**C1. Validate the rule file syntax** (needs Docker).
```bash
docker run --rm -v "$PWD/rules/falco:/rules:ro" falcosecurity/falco-no-driver:latest falco --validate /rules/kubesentinel_rules.yaml
```
```powershell
docker run --rm -v "${PWD}/rules/falco:/rules:ro" falcosecurity/falco-no-driver:latest falco --validate /rules/kubesentinel_rules.yaml
```
You should see a line ending in `Ok`. If Falco reports an error, it names the line; fix it before continuing. (The rules were schema-checked by the test-suite, but run this on *your* Falco version.)

**C2. Install Falco with the KubeSentinel rules.**
```bash
helm repo add falcosecurity https://falcosecurity.github.io/charts && helm repo update
helm install falco falcosecurity/falco -n falco --create-namespace \
  --set driver.kind=modern_ebpf --set tty=true \
  --set-file "customRules.kubesentinel\.yaml=rules/falco/kubesentinel_rules.yaml"
```
(PowerShell: put it on one line instead of using `\` continuations.) If the chart rejects a value, check the chart's `values.yaml` for the current name of the `driver` and `customRules` keys.

**C3. Wait for Falco.**
```
kubectl get pods -n falco
```
You should see the Falco pod(s) `Running` (`2/2` or `1/1`).

**C4. Confirm the rules loaded.**
```
kubectl logs -n falco -l app.kubernetes.io/name=falco -c falco --tail=200
```
Look for a line mentioning `kubesentinel.yaml` and `Falco initialized`.

**C5. Watch alerts.** Open a **second terminal** and leave this running:
```
kubectl logs -n falco -l app.kubernetes.io/name=falco -c falco -f
```

**C6. Trigger the rules one at a time** from the first terminal. After each, look at the alert terminal before moving on.

| # | Run | Expect this alert |
|---|---|---|
| 1 | `kubectl exec -it -n dev attacker-pod -- sh` (then `exit`) | Interactive Shell in Container |
| 2 | `kubectl exec -n dev attacker-pod -- cat /var/run/secrets/kubernetes.io/serviceaccount/token` | ServiceAccount Token Read by Suspicious Process |
| 3 | `kubectl exec -n dev attacker-pod -- apk add --no-cache curl` | Package Manager Run in Container |
| 4 | `kubectl exec -n dev attacker-pod -- sh -c "echo --donate-level 1 stratum+tcp://pool.invalid:3333"` | Crypto Miner Activity in Container |
| 5 | `kubectl exec -n dev attacker-pod -- nsenter -t 1 -m -u -i -n -p -- hostname` | Container Escape via nsenter (prints the *node's* hostname) |
| 6 | `kubectl exec -n dev attacker-pod -- mount -t tmpfs none /mnt` | Mount Syscall in Container |
| 7 | `kubectl exec -n dev attacker-pod -- wget -qO- --no-check-certificate https://kubernetes.default.svc/version` | Kubernetes API Client in Container |
| 8 | `kubectl exec -n dev attacker-pod -- cat /etc/shadow` | Sensitive Credential File Read in Container |
| 9 | `kubectl exec -n dev attacker-pod -- sh -c "echo test >> /etc/ks-test"` | Write to Sensitive Directory in Container |

Each alert includes namespace, pod, container, process and command line. Notes: row 5 needs `nsenter` in the image (if it says `not found`, run `kubectl exec -n dev attacker-pod -- apk add --no-cache util-linux` first); the `steal-tiller` pod from B7 also fires rows 2 and 7 by itself. The **runtime-socket** and **reverse-shell** rules are not simulated here.

**C7. Close the loop.** `kubesentinel rules` shows which Falco rule backs each posture check, so you can state: *"This cluster had a path to cluster-admin (KS-ESC-001); here is the alert that fired when I exploited it."*

## Cleanup
```
kind delete cluster --name kubesentinel
```

---

# Using it for real

```bash
# CI: scan rendered manifests, fail the build on HIGH+, publish SARIF to GitHub's Security tab
helm template ./chart > rendered.yaml
kubesentinel scan rendered.yaml --fail-on high --sarif kubesentinel.sarif
```
Use `--exclude-namespace` to skip namespaces (e.g. `kube-system`), and `--include-system` to treat `system:*` and `kube-system` identities as path sources.

Helm/Kustomize templates can't be parsed directly: render them first (`helm template`, `kubectl kustomize`). Files that fail to parse are reported as warnings, never silently dropped.

## Tuning Falco

Edit the allow-lists at the top of `rules/falco/kubesentinel_rules.yaml` (`ks_write_allowed_procs`, `ks_shadow_allowed_procs`) for your images. The shell and token rules are intentionally narrow (TTY shells, utility binaries) to keep them low-noise.

## Adding a check

1. Add a `Rule` to `kubesentinel/catalog.py` (severity, remediation, MITRE, linked Falco rule names).
2. Implement it in the matching module under `kubesentinel/checks/` using `make_finding("KS-...", ...)`.
3. Add a test. `tests/test_falco_rules.py` fails if a link points at a Falco rule that doesn't exist, or a Falco rule isn't linked from any check.

## Design notes and limitations (read before trusting a result)

- **apiGroups are ignored** when matching RBAC resources (lenient: may over-report, e.g. a custom resource named `pods`).
- **Built-in ClusterRoles** (`cluster-admin`, `admin`, `edit`, `view`) are approximated when scanning manifests; **live mode reads the real, aggregated rules** from the cluster.
- **Already-admin subjects are sinks:** a subject holding cluster-admin is reported once (`KS-RBAC-001`) and paths *through* it end at CLUSTER-ADMIN, rather than also listing node/secret paths it trivially subsumes.
- **Token-theft edges** ("read Secrets → use ServiceAccount token") only apply when long-lived token Secrets exist; modern clusters don't create them by default. The path text says so.
- **Rules with `resourceNames`** are ignored for capability checks (can't prove broad access), except for impersonation.
- **Pod Security** is read from namespace labels only; clusters enforcing policy via Kyverno/Gatekeeper will show `KS-ADM-001` false positives.
- **Admission/audit-log detections** (e.g. "privileged pod created") need Kubernetes audit events and are not included; the Falco rules are syscall-based.
- CIS references follow benchmark v1.8 numbering and are approximate; verify against your version.
- Compared with Trivy, kube-bench or Kubescape, KubeSentinel is **narrow on purpose**: RBAC path analysis plus detections linked to findings, not broad compliance coverage.

## Roadmap

K8s audit-log Falco rules · Kyverno/Gatekeeper-aware admission checks · attack-path graph in the HTML report · Helm chart for in-cluster scheduled scans · MITRE ATT&CK for Containers coverage matrix.

## License

MIT. See [LICENSE](LICENSE). **Lab manifests are intentionally insecure; run them only in a throw-away cluster.**
