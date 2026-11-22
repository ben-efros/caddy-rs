# Contributing

Welcome! You're about to help build a web server. That's either a noble pursuit or a cry for help. Either way, we're glad you're here.

A quick heads-up: this project is developed with a somewhat unreasonable amount of automation and AI assistance. Code may be written by AI, reviewed by AI, tested by AI, and occasionally explained to AI by other AI.

There are humans involved. Allegedly.

The goal is still to build something useful, correct, fast, and maintainable. The robots are here to help. They are not here to make decisions unquestioningly, invent requirements, or turn the codebase into a monument to confidently generated nonsense.

## Getting started

First, get the code:

```bash
git clone https://github.com/ben-efros/caddy-rs.git
cd caddy-rs
```

Then make sure it builds:

```bash
cargo build
cargo test
cargo fmt --all --check
cargo clippy --all-targets --all-features -- -D warnings
```

If something fails, congratulations: you've found something interesting. If everything passes, congratulations: you've found something interesting that hasn't broken yet.

## What can I work on?

Plenty. Bug fixes, performance improvements, documentation, tests, protocol support, architecture, and questionable ideas that turn out to be surprisingly good.

Before starting a large change, open an issue or discussion. This gives the humans and their silicon-based management team a chance to agree on what we're doing before anyone generates 4,000 lines of code in the wrong direction.

Small fixes? Just send a PR. We're not going to make you file a proposal to correct a typo. The machines have enough paperwork already.

## A few things we care about

- **Correctness:** Working code is better than code that merely looks plausible in a diff.
- **Performance:** Measure it. "The AI said it's faster" is not a benchmark.
- **Safety:** Don't introduce vulnerabilities. We have enough of those in the world already.
- **Maintainability:** Someone will have to understand this code six months from now. That someone might be you. It might be an AI. It might be an AI pretending to be you.
- **Tests:** If it isn't tested, it is mostly a rumor.
- **Simplicity:** Don't build a distributed autonomous microservice orchestration platform to avoid writing a function.

## Pull requests

A good PR should:

- Explain what changed and why.
- Keep the scope reasonably focused.
- Include tests where appropriate.
- Pass formatting, linting, and test checks.
- Mention any trade-offs or known limitations.

Please review your AI-generated contributions before submitting them. The autocomplete is not legally responsible for what it writes, and neither is the toaster.

AI assistance is welcome. Blindly pasting output and hoping CI develops a conscience is less welcome.

If an AI agent authored the change, that's fine. Just make sure the change has been reviewed by someone—or something—that understands what it does. A green checkmark is evidence that a check passed, not proof that the code is good.

## Tests

Run the tests. Add tests. Break things in a controlled environment rather than in production.

```bash
cargo test
```

If you add behavior, test it. If you fix a bug, add a regression test if practical. If you change performance-sensitive code, bring measurements.

"Seems fine" is not a test result. Neither is "Claude said it was fine."

## Architecture and big ideas

Big changes deserve discussion before implementation.

This includes new dependencies, major abstractions, protocol changes, architectural decisions, and anything that adds a surprising amount of complexity.

We like ambitious ideas. We also like sleeping at night.

Please don't ask an agent to redesign half the project before anyone has agreed that half the project needs redesigning. The tokens are not coming out of your paycheck, but the maintenance burden is coming out of somebody's.

## Compatibility

Avoid breaking existing behavior unless the change is intentional and discussed.

If something changes, document it. If something stops working, tell us. If something works only on your machine, that machine is now part of the problem.

## Found something broken?

Excellent. Please report it.

Include enough detail to reproduce the issue: logs, configuration, expected behavior, actual behavior, and steps to reproduce.

"Doesn't work" is a valid emotional state, but a difficult debugging strategy.

## Reviews

Reviews may involve humans, automated checks, AI-assisted analysis, or some combination of all three.

Feedback is meant to improve the code, not establish dominance over the pull request. Discuss disagreements with technical reasoning. If the robot is wrong, tell it why. If the human is wrong, tell them why too. We believe in equal-opportunity correction.

Automated review is useful, but it is not an oracle. It can miss bugs, invent bugs, misunderstand intent, and occasionally write an entire dissertation about a missing semicolon.

Use judgment.

## The important bit

This project is built by people, tools, agents, and an increasingly complicated pile of automation. None of that changes the basic rules:

- Be curious.
- Be constructive.
- Write good code.
- Test your work.
- Explain your decisions.
- Don't trust generated code just because it arrived with confidence.
- Don't trust humans just because they have a pulse.

Build interesting things. Break things responsibly. Fix what you break.

And if the bots start approving their own pull requests, please tell someone. Preferably a human.
