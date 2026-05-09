/**
 * deploy_vault.js — Deploy VulnerableVault + UUPSProxy to a local Hardhat node.
 *
 * Usage:
 *   npx hardhat run scripts/deploy_vault.js --network localhost
 *
 * Output:
 *   artifacts/demo_deployment.json  — proxy + impl addresses, deployer info
 *
 * WARNING: Uses Hardhat's well-known test private key.
 *          NEVER deploy to mainnet or any live network with this key.
 */
import hre from "hardhat"
import { writeFileSync, mkdirSync } from "fs"

const { ethers } = hre

async function main() {
  const [deployer] = await ethers.getSigners()
  console.log(`Deployer: ${deployer.address}`)

  // ── 1. Deploy VulnerableVault implementation ────────────────────────────────
  console.log("\nDeploying VulnerableVault implementation…")
  const VulnerableVault = await ethers.getContractFactory("VulnerableVault")
  const impl = await VulnerableVault.deploy()
  await impl.waitForDeployment()
  const implAddress = await impl.getAddress()
  console.log(`  Implementation: ${implAddress}`)

  // ── 2. ABI-encode initialize(deployer) ──────────────────────────────────────
  // Passing initData to the proxy constructor causes it to delegatecall
  // initialize() atomically — safe against front-running.
  const initData = VulnerableVault.interface.encodeFunctionData("initialize", [
    deployer.address,
  ])

  // ── 3. Deploy UUPSProxy(impl, initData) ─────────────────────────────────────
  console.log("Deploying UUPSProxy…")
  const UUPSProxy = await ethers.getContractFactory("UUPSProxy")
  const proxy = await UUPSProxy.deploy(implAddress, initData)
  await proxy.waitForDeployment()
  const proxyAddress = await proxy.getAddress()
  console.log(`  Proxy:          ${proxyAddress}`)

  // ── 4. Verify initialization via proxy ──────────────────────────────────────
  const vault = VulnerableVault.attach(proxyAddress)
  const owner = await vault.owner()
  if (owner.toLowerCase() !== deployer.address.toLowerCase()) {
    throw new Error(`owner mismatch: expected ${deployer.address}, got ${owner}`)
  }
  console.log(`  Owner verified: ${owner}`)

  // ── 5. Write artifacts/demo_deployment.json ──────────────────────────────────
  mkdirSync("artifacts", { recursive: true })

  const result = {
    proxyAddress,
    implAddress,
    deployerAddress: deployer.address,
    // Hardhat account[0] deterministic test key — DO NOT use with real funds
    privateKey:
      "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
    chainId: hre.network.config.chainId ?? 31337,
    deployedAt: new Date().toISOString(),
  }

  writeFileSync(
    "artifacts/demo_deployment.json",
    JSON.stringify(result, null, 2)
  )

  console.log("\nWrote artifacts/demo_deployment.json")
  console.log(JSON.stringify(result, null, 2))
  console.log("\nDeploy complete. Use proxyAddress in your /heal request.")
}

main().catch((e) => {
  console.error(e)
  process.exit(1)
})
