"""Framework-owned package facts; never substitute for Runner judgment."""
from typing import Literal

from pydantic import Field

from .handoff import HandoffDraftV1, Record
from .schema import ServiceCompletion


class CapturedArtifact(Record):
    path: str
    kind: Literal["file", "directory", "symlink", "missing"]
    sha256: str | None = None
    size: int | None = None
    mode: int | None = None
    uid: int | None = None
    gid: int | None = None
    link: str | None = None
    storage: str = "image"


class StateArchive(Record):
    destination: str
    file: str
    sha256: str
    size: int
    excluded_mounts: list[str]


class DeliveryManifestV1(Record):
    schema_version: Literal[1] = 1
    format: Literal["fmst-agent-delivery"] = "fmst-agent-delivery"
    task_id: str
    target: str
    created_at: float
    source_result_version: int
    handoff_origin: Literal["same_session", "retrospective_session"]
    completion: ServiceCompletion
    handoff: HandoffDraftV1
    inputs: dict = Field(description="Recorded input identities, without claiming new upstream analysis.")
    image: dict = Field(description="Exact final image ID, exact base image ID and private local storage scope.")
    container_config: dict = Field(description="Whitelisted resource, capability and runtime settings used by the original container.")
    execution: dict = Field(description="Recorded GuestWeave execution and loaded file identities when registered; unregistered stays explicit.")
    capture: dict = Field(description="Live nonatomic filesystem capture, the current verified service/init identity (original completion or a delivery restart), excluded runtime state and any unresolved gaps. Restart identity does not replace original business observations.")
    artifacts: list[CapturedArtifact]
    state_archives: list[StateArchive]


def render_readme(manifest: DeliveryManifestV1) -> str:
    h = manifest.handoff
    lines = [f"# {manifest.target}", "", h.summary, "", "## 使用", "",
             "本包需要 Python 3.12+ 和原 Rootless Docker 引擎；镜像仅保存在本机私有引擎。",
             "在本目录执行。默认复用原实例，down 保留容器及其数据。", "", "```sh",
             "./fmst up", "./fmst open", "./fmst status", "./fmst logs", "./fmst down", "```", "",
             "显式另建实例：`./fmst up --new-instance NAME`。随后用 `--instance NAME` 管理它。",
             "新实例从交付快照建立；原实例配置不重置。启动只核对进程回执，不重判业务。", "",
             f"原生入口：{h.access.native_url}", "", h.access.instructions, "",
             f"启动配方：{h.startup.availability}。重启验证：{h.restart_verification.status}。",
             h.restart_verification.details]
    if h.startup.unavailable_reason:
        lines += [h.startup.unavailable_reason]
    lines += ["", "## 工程说明", ""]
    for finding in h.analysis:
        lines += [f"### {finding.issue}", "", f"原因判断：{finding.assessment}。{finding.explanation}", "",
                  *[f"- 修改：{change}" for change in finding.changes], "", f"结果：{finding.outcome}", "",
                  *[f"- 证据：`{ref.path}` — {ref.purpose}" for ref in finding.evidence], ""]
    lines += ["## 已观察到的行为", "",
              *[f"- {item.operation}：{item.observed}" for item in manifest.completion.interactions], "",
              "## 限制", "", *[f"- {item}" for item in dict.fromkeys(manifest.completion.limitations + h.limitations)],
              "", "## 保存范围", "",
              "`delivery.json` 是本说明和启动器的数据源。最终镜像保存容器文件系统中的修改；",
              "运行进程、内存、IPC 和命名空间不在镜像内，由启动配方重建。",
              "挂载中的指定文件或目录另存数据归档。原实例的 tmpfs 数据在 down 前保存当前快照，up 先恢复再启动；",
              "新实例使用命名卷，初次恢复之后保留用户修改。快照是运行中捕获，不保证事务一致性或包含随后发生的写入。",
              "交付启动默认关闭自动 core dump，已有诊断证据保留。硬限制不变，需要新的 core 时可显式恢复进程的软限制。",
              "原完成记录保留当时的业务观察；重启后的进程身份单独核对，不复用旧 PID。",
              "捕获时服务继续运行，文件快照不承诺数据库事务一致性。",
              "原生 Agent 历史在私有 session volume 及宿主私有备份中保留，不进入交付镜像。",
              "证据路径指向最终镜像内文件，摘要和外置数据在 manifest 中列出。", "",
              f"捕获状态：{manifest.capture['status']}",
              *[f"- 未完整捕获：{gap}" for gap in manifest.capture.get("gaps", [])], ""]
    return "\n".join(lines)
