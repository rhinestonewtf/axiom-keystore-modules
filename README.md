# Axiom Keystore Modules

A proof of concept for integrating ERC-7579 modules with [Axiom Keystore](https://keystore-docs.axiom.xyz/introduction) - a ZK rollup for secure key management.

## Core Components

### ERC7579KeystoreModuleBase
Base module enabling Keystore integration for ERC-7579 modules:
- Processes IMT proofs 
- Verifies keystore addresses
- Handles inclusion/exclusion proofs

### Example Modules
- **KeystoreValidator**: Stateless validator multiplexor using the Axiom Keystore state as source of truth.
- **KeystoreOwnableValidator**: [OwnableValidator](https://github.com/rhinestonewtf/core-modules/blob/main/src/OwnableValidator/OwnableValidator.sol) empowered with optional Keystore state usage.

### Auxiliary Contracts
- **KeystoreCache**: Utility for caching keystore roots and L1 blocks

## Utility Libraries
- **KeystoreModuleUtils**: IMT proof processing utilities
