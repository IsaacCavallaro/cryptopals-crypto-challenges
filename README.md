# Cryptopals Crypto Challenges Solutions

> ⚠️ **NOTE:** This code is part of my initial attempt to document and share my journey through the [Cryptopals Crypto Challenges](https://www.cryptopals.com/). The focus is on understanding and learning the concepts, not on providing optimised or production-ready solutions.

## Overview

This repository contains Python scripts for solving the Cryptopals challenges. Each challenge is in its own file, organised by set. The goal of this project is to not only solve the challenges but also to provide clear, documented solutions for anyone following along.

## How to Install Locally

1. **Clone the Repository**  
   First, clone the repository from GitHub:

```bash
git clone git@github.com:IsaacCavallaro/cryptopals-crypto-challenges.git
```

---

2. **Set Up a Virtual Environment**  

```bash
python3 -m venv venv
source venv/bin/activate  # On macOS/Linux
```

# How to Run the Scripts

Each challenge script is located in the `src/set_{x}/` directory and can be run individually. Here's how you can run them:

1. Activate the Virtual Environment
Before running any script, ensure your virtual environment is activated:

```bash
source venv/bin/activate  # On macOS/Linux
```

2. Run a challenge script
For example, to run challenge one:

```bash
python src/set_one/challenge_one.py
```

# How to Run the Tests

- Assuming you are in the root directory of the project:

```bash
pytest src/set_{x}/tests/{x}.py
```
