const hre = require("hardhat");
const fs = require("fs");
const path = require("path");

async function main() {
  const Factory = await hre.ethers.getContractFactory("MedicalRecords");
  const c = await Factory.deploy();
  await c.waitForDeployment();
  const address = await c.getAddress();
  const artifact = await hre.artifacts.readArtifact("MedicalRecords");
  const chainId = Number((await hre.ethers.provider.getNetwork()).chainId);

  fs.writeFileSync(
    path.join(__dirname, "../backend/contract.json"),
    JSON.stringify({ address, chainId, abi: artifact.abi }, null, 2)
  );
  console.log("MedicalRecords deployed to:", address, "(chainId", chainId + ")");
  console.log("Wrote backend/contract.json");
}

main().catch((e) => { console.error(e); process.exit(1); });
