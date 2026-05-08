# How To Use the Default Rule Catalog

The default rule catalog is the built-in safety floor for common Terraform risks.

## In the web UI

1. Look at the right-side **Default Rules** list.
2. Click a rule ID such as `TG008`.
3. Review the rule detail in the main panel.
4. If your organization needs ownership or compliance metadata for that control, create an
   enterprise policy that maps to your internal process.

## Built-in rule range

Default rules use `TG001` through `TG020`. New enterprise policies start at the next available rule
number, such as `TG021`.

## When to create an enterprise policy

Create an enterprise policy when a built-in rule needs:

- A control owner
- A compliance standard or control ID
- A risk tier
- A remediation instruction that matches your platform standards
- An approval workflow
