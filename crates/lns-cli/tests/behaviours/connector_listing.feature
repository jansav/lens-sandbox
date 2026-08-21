Feature: listing connectors on a machine that has none
  Nothing ships inside `lns`, so an empty catalog is the state of every fresh
  install rather than an edge case. `lns connector list` says so and names the
  next step for a person, while a script still gets an empty array to iterate.

  Scenario: An empty catalog says so rather than printing a bare header
    When the developer runs "lns connector list"
    Then the output points at declaring a connector

  Scenario: An empty catalog is an empty array for a script
    When the user runs connector command "list --format json"
    Then the output is an empty JSON array
