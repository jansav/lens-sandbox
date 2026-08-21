Feature: a definition's credential requirements gate the launch before boot
  The sign-in gate for a declared credential an oauth connector supplies fires
  on the host before any microVM boots, so this wiring confirmation runs
  virt-free through the real binaries: the CLI carries the definition on the
  wire, the service plans it, and the launch is aborted with guidance. No
  document names a connector, so nothing else gates here.

  Scenario: a declared credential an oauth connector supplies aborts when the sign-in cannot complete
    Given a clean lns cache home
    And the home's connector catalog declares an oauth connector "some-oauth" signing in at "http://127.0.0.1:1"
    And the Lens Sandbox service is running in that home
    And the project definition declares credential "SOME_OAUTH_TOKEN" for "api.some-oauth.example"
    When the user runs the sandbox definition
    Then the exit code is non-zero
    And the output contains "needs a sign-in before the workload starts"
    And the output contains "launch aborted"
