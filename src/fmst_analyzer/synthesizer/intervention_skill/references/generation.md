# Firmenstein execution generation

Use this reference only for execution generation, with the supplied Unit Contract,
[candidate engineering](candidate-engineering.md) and selected GuestWeave
engineering/ABI references. The framework defines the API; the supplied shell
defines this application's module layout and imports. These authoring permissions
do not define a later container Runner's permissions.

Earlier Unit source remains read-only during generation; the task supplies
permitted imports and paths for sharing its public state surface.

Derive expected behavior from the Plan, Analyzer evidence and original code,
not from generated implementation. Resolve applicability inputs at their
actual guest source, including globals and complete pointer chains. Cover
the relevant normal, boundary, output, state and retained native-call behavior.
Do not weaken an assertion to make a candidate pass.

Only edit the supplied Unit files and exact test file. Run the Controller-bound
`verify_unit` tool; its Cargo manifests and test target are not Agent-selected.
Write a concrete candidate even when `allowed_refinement_scope=[]`; that field
describes later legacy refinement permission, not whether to generate code.
The implementation Agent also authors and checks the MockIIBContextOps tests;
no independent semantic Reviewer is required. Runtime supplies dynamic evidence.
Preserve a concrete candidate and its actual failed checks when reporting
completion; completed delivery does not mean successful build/test or guest
readiness. Return unable only when no concrete candidate can be written.
