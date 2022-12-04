# Contributing code to `shellclear`

Shellclear is open source and we love to receive contributions from our community — you!
There are many ways to contribute, from writing more sensitive patterns, improving the documentation, submitting bug reports and feature requests or writing code.

## How to contribute
The preferred and easiest way to contribute changes to the project is to fork it on GitHub, and then create a pull request to ask us to pull your changes into our repo.
We use GitHub's pull request workflow to review the contribution, and either ask you to make any refinements needed or merge it and make them ourselves.

Things that should go into your PR description:

 - References to any bugs fixed by the change
 - Notes for the reviewer that might help them to understand why the change is necessary or how they might better review it

Your PR must also:

 - be based on the `main` branch
 - adhere to the [code style](#code-style)
 - pass the [test suite](#tests)
 - include [sensitive pattern](#new-pattern)


## Code style

We use the standard Rust code style, and enforce it with `rustfmt`/`cargo fmt`.
If you're using [`rustup`](https://rustup.rs), the nightly version of `rustfmt` can be installed by doing the following:

```
rustup component add rustfmt --toolchain nightly
```

And then format your code by running:

```
cargo +nightly fmt
```

We also enforce some code style rules via [`clippy`](https://github.com/rust-lang/rust-clippy).


## Tests

Run unitest by the following command:

```sh
cargo test
```

### Create test snapshots
To capture the snapshots test we using [insta](https://github.com/mitsuhiko/insta) rust project. you can see the snapshot changes / new snapshot by running the command:
```sh
cargo insta test --review
```

## New Pattern

If your PR includes a new sensitive data pattern/s you need add a tests by the following steps:
1. create a new yaml file in [folder](shellclear/tests/suites_sensitive_patterns). name of the file must be equal to the pattern id (lowercase an _ only)
2. the file need to contain list of test
```
- name: # test name
  test: # the content to run the regex on
  expected: # the regex reguls
```
3. After adding the tests, add the snapshot (*.snap) results to the commit. read more [here](#create-test-snapshots).
