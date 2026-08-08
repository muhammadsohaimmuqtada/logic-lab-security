# Contributing

Logic Lab accepts challenge additions that model realistic business-logic failures while preserving the host safety boundary.

A new challenge should include:

- a believable business workflow and intended rule;
- a non-obvious server-side assumption that violates that rule;
- a learner objective without exploit spoilers;
- a deterministic challenge flag or success condition;
- a challenge-contract regression test proving exploitability;
- an instructor-guide explanation;
- normal-flow tests showing the surrounding feature still works.

Avoid challenges whose primary lesson is host compromise, destructive behavior, malware execution, arbitrary shell commands, or public-target exploitation.
