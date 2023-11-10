---
# https://vitepress.dev/reference/default-theme-home-page
layout: home

hero:
  name: "Firedancer 🔥💃"
  text: "Solana validator"
  tagline: A new Solana validator client, built from the ground up for performance
  actions:
    - theme: brand
      text: Get Started
      link: /guide/getting-started
    - theme: alt
      text: View on GitHub
      link: https://github.com/firedancer-io/firedancer

features:
  - title: Fast
    details: Designed from the ground up to be fast. The concurrency model is borrowed from the low latency trading space, and the code contains many novel high performance reimplementations of core Solana primitives.
  - title: Secure
    details: The architecture of the validator allows it to run with a highly restrictive sandbox and almost no system calls.
  - title: Independent
    details: Firedancer is written from scratch. This brings client diversity to the Solana network and helps it stay resilient to supply chain attacks in build tooling or dependencies.
---
