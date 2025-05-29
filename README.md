# Merkle Tree Ladder (MTL) Integration with DNSSEC - Simulation

This project simulates the integration of a **Merkle Tree Ladder (MTL)** mechanism into the **Zone Signing Key (ZSK)** workflow of **DNSSEC**. The goal is to evaluate the potential enhancements in security and efficiency for DNS record verification when using MTL. The simulation also demonstrates how the generated **MTL signature** can be signed using **Falcon-512**, a post-quantum signature scheme, to prepare for quantum-safe DNSSEC deployments.

## 📌 Project Objectives

- Simulate DNS Resource Record Sets (RRsets) with common types: `A`, `AAAA`, and `TXT`.
- Construct a **Merkle Tree Ladder** from DNS resource records.
- Generate MTL signatures by combining current and previous Merkle roots.
- Generate Merkle proofs to verify the integrity of individual resource records.
- Simulate signing the MTL signature using **Falcon-512** (handled externally).

## 🔐 Cryptographic Workflow

- **SHA-256**: Used to hash DNS resource record data and construct the Merkle tree.
- **Merkle Tree Ladder (MTL)**: Builds hierarchical hash trees for each RRSet.
- **MTL Signature**: Combines current and previous Merkle roots into a chained hash.

## ⚙️ Installation & Execution

### 🧷 Dependencies

Install OpenSSL development libraries for SHA-256 hashing:

```bash
sudo apt update
sudo apt install libssl-dev
```

### 🔧 Compile the Simulation Code

```bash
gcc mtl_dnssec.c -o mtl_dnssec -lcrypto
```

Replace `mtl_dnssec.c` with your actual filename if different.

### ▶️ Run the Program

```bash
./mtl_dnssec
```

You will be prompted to enter a query type:

```plaintext
Enter query (A, AAAA, TXT) or 'exit': A
```

The output will include:
- Queried RRSet records
- Constructed Merkle Tree Root
- Generated MTL Signature
- Simulated TXT record to hold the MTL Signature
- Merkle Proof for the first leaf node

### 🔐 Falcon-512 Signing (Optional)

The generated MTL Signature can be signed using Falcon-512 offline. Example (outside this code):

```bash
falcon512-sign sk.pem mtl_signature.bin > mtl_signature.sig
```

Verification can be performed with:

```bash
falcon512-verify pk.pem mtl_signature.bin mtl_signature.sig
```

## 📂 Code Structure Overview

| Function / Struct                  | Purpose                                                  |
|------------------------------------|----------------------------------------------------------|
| `RRRecord`, `RRSet`                | Store DNS resource records                               |
| `MerkleTree`                       | Holds the full tree and its levels                       |
| `build_merkle_tree_levels()`       | Constructs the Merkle Tree Ladder                        |
| `compute_mtl_signature()`          | Generates chained root hash (MTL Signature)              |
| `generate_merkle_proof()`          | Generates proof path for a leaf record                   |
| `query_rrset()`                    | Handles RRSet query and MTL logic                        |

## ✍️ Author

**Rajdeep Das** – PhD Scholar  
**Institute of Engineering and Management (IEM), Kolkata**  
**Domains**: IoT, Network Security, AIML 

*This project is a simulation for research purposes and is not intended for production use without further testing and validation.*
