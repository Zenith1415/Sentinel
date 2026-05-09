/**
 * deploy_unpatchable.js — Deploy all UnpatchableVault contracts to local Hardhat node.
 *
 * Usage:
 *   npx hardhat run scripts/deploy_unpatchable.js --network localhost
 *
 * Output:
 *   artifacts/unpatchable_deployment.json  — all contract addresses
 */
import hre from "hardhat"
import { writeFileSync, mkdirSync } from "fs"

const { ethers } = hre

async function main() {
  const [deployer] = await ethers.getSigners()
  console.log(`Deployer: ${deployer.address}`)

  // ── Deploy supporting contracts ──────────────────────────────────────────

  console.log("\nDeploying cross-contract reentrancy triangle (VaultA/B/C)…")
  const VaultA = await ethers.getContractFactory("VaultA")
  const VaultB = await ethers.getContractFactory("VaultB")
  const VaultC = await ethers.getContractFactory("VaultC")

  const vaultA = await (await VaultA.deploy()).waitForDeployment()
  const vaultB = await (await VaultB.deploy()).waitForDeployment()
  const vaultC = await (await VaultC.deploy()).waitForDeployment()

  const aAddr = await vaultA.getAddress()
  const bAddr = await vaultB.getAddress()
  const cAddr = await vaultC.getAddress()

  await vaultA.initialize(deployer.address, bAddr)
  await vaultB.initialize(cAddr)
  await vaultC.initialize(aAddr)

  console.log(`  VaultA: ${aAddr}`)
  console.log(`  VaultB: ${bAddr}`)
  console.log(`  VaultC: ${cAddr}`)

  console.log("\nDeploying storage-collision contracts (Logic/Library)…")
  const Logic   = await ethers.getContractFactory("LogicContract")
  const Library = await ethers.getContractFactory("LibraryContract")
  const logic   = await (await Logic.deploy()).waitForDeployment()
  const library = await (await Library.deploy()).waitForDeployment()
  const logicAddr   = await logic.getAddress()
  const libraryAddr = await library.getAddress()
  await logic.setLibrary(libraryAddr)
  console.log(`  LogicContract:   ${logicAddr}`)
  console.log(`  LibraryContract: ${libraryAddr}`)

  console.log("\nDeploying MockOracle…")
  const Oracle = await ethers.getContractFactory("MockOracle")
  const oracle = await (await Oracle.deploy()).waitForDeployment()
  const oracleAddr = await oracle.getAddress()
  console.log(`  MockOracle: ${oracleAddr}`)

  console.log("\nDeploying UnpatchableVault (main)…")
  const Vault = await ethers.getContractFactory("UnpatchableVault")
  const vault = await (await Vault.deploy()).waitForDeployment()
  const vaultAddr = await vault.getAddress()

  await vault.initialize(
    deployer.address,
    oracleAddr,
    ethers.ZeroAddress,  // governance token — not needed for demo
    logicAddr,
  )

  // Seed vault with some ETH to make exploits visible
  await vault.deposit({ value: ethers.parseEther("5") })
  console.log(`  UnpatchableVault: ${vaultAddr}  (seeded with 5 ETH)`)

  // ── Write artifacts ──────────────────────────────────────────────────────

  mkdirSync("artifacts", { recursive: true })
  const result = {
    vaultAddress:    vaultAddr,    // use THIS in the dashboard
    vaultAAddress:   aAddr,
    vaultBAddress:   bAddr,
    vaultCAddress:   cAddr,
    logicAddress:    logicAddr,
    libraryAddress:  libraryAddr,
    oracleAddress:   oracleAddr,
    deployerAddress: deployer.address,
    privateKey: "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
    chainId:     hre.network.config.chainId ?? 31337,
    deployedAt:  new Date().toISOString(),
    note: "Paste vaultAddress into the dashboard Contract Address field and select UnpatchableVault preset.",
  }

  writeFileSync("artifacts/unpatchable_deployment.json", JSON.stringify(result, null, 2))
  console.log("\nWrote artifacts/unpatchable_deployment.json")
  console.log(JSON.stringify(result, null, 2))

  console.log("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
  console.log("  Deploy complete.")
  console.log(`  → Paste into dashboard: ${vaultAddr}`)
  console.log("  → Select '💀 UnpatchableVault' preset in the UI")
  console.log("  → Click ▶ Heal — pipeline will escalate to SLOW PATH")
  console.log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
}

main().catch(e => { console.error(e); process.exit(1) })
