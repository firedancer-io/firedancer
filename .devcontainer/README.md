# Development Container for Firedancer

This directory contains the VS Code Dev Container configuration for Firedancer development.

## What is a Dev Container?

A development container is a running container that provides a fully configured development environment. It allows you to:
- Use a container as a full-featured development environment
- Ensure consistent development environments across your team
- Get started quickly without manual setup

## Using the Dev Container

### Prerequisites
- [Docker Desktop](https://www.docker.com/products/docker-desktop) or [Docker Engine](https://docs.docker.com/engine/install/)
- [Visual Studio Code](https://code.visualstudio.com/)
- [Dev Containers extension](https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-containers) for VS Code

### Getting Started

1. Open the Firedancer repository in VS Code
2. Press `F1` and select **Dev Containers: Reopen in Container**
3. Wait for the container to build and start (this may take several minutes on first run)
4. Once ready, you'll have a fully configured development environment

The container will automatically:
- Install all required system dependencies
- Initialize git submodules
- Run `./deps.sh +dev` to set up build dependencies
- Configure C/C++ tools and extensions

### What's Included

The dev container includes:
- Ubuntu 22.04 base image
- All build tools and dependencies (gcc, make, cmake, etc.)
- C/C++ development tools
- GitHub Copilot integration
- LLDB debugger support
- Pre-configured VS Code settings for Firedancer code style

### Building

Once inside the container, you can build Firedancer:

```bash
make -j
```

Or run the development environment:

```bash
make -j run
```

## Customization

You can customize the dev container by editing `devcontainer.json`. Common customizations include:
- Adding additional VS Code extensions
- Installing additional packages
- Changing environment variables
- Adjusting VS Code settings

For more information, see the [Dev Containers documentation](https://code.visualstudio.com/docs/devcontainers/containers).
