# Contributing

Logic Lab accepts changes that improve the training platform while preserving its deliberately narrow safety boundary.

## Challenge design standard

A new challenge must include:

- a believable business workflow and explicit business invariant;
- a non-obvious server-side assumption that violates that invariant;
- a learner objective that does not reveal the exploit mechanism;
- a learner-scoped flag or equally deterministic success condition;
- a challenge-contract regression test proving the intended exploitability;
- normal-flow coverage proving surrounding product behavior still works;
- instructor documentation;
- confirmation that an unrelated endpoint does not provide a substantially easier shortcut to the same objective.

Do not add routes named `/vulnerable`, comments that disclose the flaw to learners, or UI controls whose only purpose is to point directly at the exploit.

## Safety boundary

Do not introduce challenges whose primary lesson requires:

- host command execution;
- arbitrary host file access;
- container escape;
- destructive malware behavior;
- public-target exploitation;
- persistence outside the application instance data.

If a change expands impact beyond the intended local training application, treat it as a project security defect rather than a challenge.

## Regression expectations

Every pull request should pass:

```bash
python -m compileall app tests scripts
pytest -q
python scripts/build_learner_bundle.py
docker build -t logic-lab .
```

CI additionally boots the built image and checks the live health endpoint.

When changing an existing challenge, update its exploit-contract test and instructor documentation in the same change. Do not silently harden away an intentional challenge or broaden it with unrelated accidental weaknesses.

See `docs/ARCHITECTURE.md` for the identity, flag, deployment, and challenge-contract model.
