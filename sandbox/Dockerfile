# Blackwing per-job sandbox.
# One container per engagement, torn down after the run. It receives only that job's
# artifacts + scope.yaml (mounted at /job) and runs the engine with BLACKWING_ENGINE=1 so the
# control-plane hooks fail closed. No credentials are baked in — the token, if any, is passed
# via the in-memory secrets store in the orchestrator, never into the image.
FROM python:3.12-slim

# Static/analysis tooling only. Add apktool (needs a JRE) for Android decode; git for source.
RUN apt-get update && apt-get install -y --no-install-recommends \
        git ca-certificates default-jre-headless unzip curl \
    && rm -rf /var/lib/apt/lists/*

# apktool (manifest/resource decode for Track C).
RUN curl -fsSL -o /usr/local/bin/apktool \
        https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool \
    && curl -fsSL -o /usr/local/bin/apktool.jar \
        https://github.com/iBotPeaches/Apktool/releases/download/v2.9.3/apktool_2.9.3.jar \
    && chmod +x /usr/local/bin/apktool /usr/local/bin/apktool.jar || true

WORKDIR /opt/blackwing
# lib/ is stdlib-only; copy the engine, hooks, and orchestrator helpers the engine imports.
COPY lib/ ./lib/
COPY bin/ ./bin/
COPY orchestrator/ ./orchestrator/
COPY .claude/ ./.claude/
COPY config/ ./config/

ENV PYTHONPATH=/opt/blackwing \
    BLACKWING_ENGINE=1 \
    BLACKWING_JOB_DIR=/job \
    BLACKWING_SCOPE=/job/scope.yaml

# Non-root: the sandbox never needs privilege.
RUN useradd -m -u 10001 runner && chown -R runner:runner /opt/blackwing
USER runner

# The job dir is bind-mounted read/write at /job by the lifecycle runner.
ENTRYPOINT ["python", "-m", "bin.run_job", "/job"]
