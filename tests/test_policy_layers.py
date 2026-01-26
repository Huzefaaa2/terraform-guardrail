from terraform_guardrail.scanner.scan import _resolve_policy_layers


def test_resolve_policy_layers_base_env_app() -> None:
    bundle_ids, layer_names = _resolve_policy_layers(
        policy_bundle=None,
        policy_layers=None,
        policy_base="baseline",
        policy_env="prod",
        policy_app="payments",
    )
    assert bundle_ids == ["baseline", "prod", "payments"]
    assert layer_names == ["base", "env", "app"]


def test_resolve_policy_layers_from_bundle_list() -> None:
    bundle_ids, layer_names = _resolve_policy_layers(
        policy_bundle="baseline,prod,app",
        policy_layers=None,
        policy_base=None,
        policy_env=None,
        policy_app=None,
    )
    assert bundle_ids == ["baseline", "prod", "app"]
    assert layer_names == ["layer1", "layer2", "layer3"]
