# Ensure the Action Registry (Layer 1) is loaded and bound to the Action class.
# This must happen before any module uses Action.is_known() / is_mutating().
import core.action_registry  # noqa: F401
