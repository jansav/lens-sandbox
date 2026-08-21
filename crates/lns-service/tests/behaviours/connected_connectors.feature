Feature: only a connector this directory connected arms at launch
  No artifact names a connector: which method supplies a credential is
  decided per machine, so a definition cannot ask for one. A connector the
  developer connected in this directory seeds its placeholder env var and
  opens the route it declares; one nobody connected does neither, even when
  a value for it is already bound on this machine. Consent stays reactive
  and per-directory: the first time a workload reaches a connector's domain
  it is offered a live connect, and accepting it records the connection in
  the per-machine grant record rather than in any document. A sandbox that
  must have a credential declares a `spec.credentials` slot instead (see
  credential_at_boot.feature). Real secrets never enter the artifact or the
  workload.

  Scenario: A connector connected in this directory arms at launch
    Given the machine catalog has a credential connector "some-provider" managing "SOME_TOKEN" with a route to "api.some-provider.example"
    And the directory's lns-local-mixin.yaml connects "some-provider"
    When the sandbox is launched
    Then the workload's environment contains the "SOME_TOKEN" placeholder
    And the running policy allows the "api.some-provider.example" route

  Scenario: A connected connector's machine-stored value arms at the boundary at launch
    Given the machine catalog has a credential connector "some-provider" managing "SOME_TOKEN" with a route to "api.some-provider.example"
    And the directory's lns-local-mixin.yaml connects "some-provider"
    And the per-machine credential store has a stored value for "some-provider"
    When the sandbox is launched
    Then the boundary injection for "some-provider" is armed with the stored value

  Scenario: A connector nobody connected seeds no placeholder and opens no route
    Given the machine catalog has a credential connector "some-provider" managing "SOME_TOKEN" with a route to "api.some-provider.example"
    And the directory's lns-local-mixin.yaml connects no connectors
    When the sandbox is launched
    Then the workload's environment does not seed the "SOME_TOKEN" placeholder
    And the running policy does not allow the "api.some-provider.example" route
    And "some-provider" is offered for a reactive connect

  Scenario: An unconnected connector's machine-stored value stays unarmed
    Given the machine catalog has a credential connector "some-provider" managing "SOME_TOKEN" with a route to "api.some-provider.example"
    And the directory's lns-local-mixin.yaml connects no connectors
    And the per-machine credential store has a stored value for "some-provider"
    When the sandbox is launched
    Then the boundary injection for "some-provider" stays unarmed
    And "some-provider" is offered for a reactive connect

  Scenario: A committed overlay this workload never granted does not arm the machine-stored value
    Given the machine catalog has a credential connector "some-provider" managing "SOME_TOKEN" with a route to "api.some-provider.example"
    And the directory's lns-local-mixin.yaml connects "some-provider"
    And the per-machine credential store has a stored value for "some-provider"
    And this workload has no grant for "some-provider"
    When the sandbox is launched
    Then the workload's environment contains the "SOME_TOKEN" placeholder
    And the boundary injection for "some-provider" stays unarmed

  Scenario: A grant the bare run earned does not arm a run that layers a mixin onto it
    Given the machine catalog has a credential connector "some-provider" managing "SOME_TOKEN" with a route to "api.some-provider.example"
    And the directory's lns-local-mixin.yaml connects "some-provider"
    And the per-machine credential store has a stored value for "some-provider"
    And the run composes the mixin "ghcr.io/acme/obs-tools"
    When the sandbox is launched
    Then the workload's environment contains the "SOME_TOKEN" placeholder
    And the boundary injection for "some-provider" stays unarmed

  Scenario: An oauth connector nobody connected does not block the launch; it is offered
    Given the machine catalog has an oauth connector "some-oauth"
    And the directory's lns-local-mixin.yaml connects no connectors
    When the sandbox is launched
    Then the launch is not gated on a sign-in
    And "some-oauth" is offered for a reactive connect

  Scenario: Accepting a reactive connect persists to the directory policy, never the definition
    Given a launched sandbox and a machine catalog connector "some-provider"
    When the developer approves a new destination "api.example.test" with "always allow"
    Then the allow rule is written to the directory's lns-local-mixin.yaml
    And the sandbox definition is not modified

  Scenario: A declared credential does not open a route past a local deny-by-default
    Given the machine catalog has a credential connector "some-provider" managing "SOME_TOKEN" with a route to "api.some-provider.example"
    And the sandbox definition declares a credential "SOME_TOKEN" for "api.some-provider.example"
    And the directory's lns-local-mixin.yaml denies all by default
    When the sandbox is launched
    Then a workload request to "api.some-provider.example" is denied by policy
