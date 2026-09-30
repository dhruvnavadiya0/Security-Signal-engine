from src.core.agent_coordinator import AgentCoordinator


def test_agent_coordinator_persists_parent_and_status(tmp_path):
    coordinator = AgentCoordinator(str(tmp_path / "agents.db"))
    root = coordinator.register("root", "map the target")
    child = coordinator.register("api", "review API endpoints", root.id)
    coordinator.update_status(child.id, "completed")

    graph = coordinator.graph()
    assert graph[1]["parent_id"] == root.id
    assert graph[1]["status"] == "completed"
    assert child.id in coordinator.snapshot()