// Temporary debug code to add to the console
// Run this in the browser console after the dashboard loads

// Function to inspect agent data more thoroughly
function inspectAgentData() {
  // This will help us see what's actually in the data
  console.log("=== MANUAL INSPECTION OF AGENT DATA ===");
  
  // Get the latest inventory data
  const inventoryData = agentData.filter(data => data.message_type === 'inventory');
  console.log("Found inventory entries:", inventoryData.length);
  
  inventoryData.forEach((data, index) => {
    console.log(`\nInventory ${index + 1}:`);
    console.log("Keys:", Object.keys(data.data));
    
    // Check each key to see if it contains arrays
    Object.keys(data.data).forEach(key => {
      const value = data.data[key];
      if (Array.isArray(value)) {
        console.log(`  ${key}: Array with ${value.length} items`);
        if (value.length > 0) {
          console.log(`    First item:`, value[0]);
        }
      } else if (typeof value === 'object' && value !== null) {
        console.log(`  ${key}: Object with keys:`, Object.keys(value));
      } else {
        console.log(`  ${key}: ${typeof value} - ${value}`);
      }
    });
  });
  
  // Check SBOM data
  const sbomData = agentData.filter(data => data.message_type === 'sbom');
  console.log("\nFound SBOM entries:", sbomData.length);
  
  sbomData.forEach((data, index) => {
    console.log(`\nSBOM ${index + 1}:`);
    console.log("Keys:", Object.keys(data.data));
    
    Object.keys(data.data).forEach(key => {
      const value = data.data[key];
      if (Array.isArray(value)) {
        console.log(`  ${key}: Array with ${value.length} items`);
        if (value.length > 0) {
          console.log(`    First item:`, value[0]);
        }
      } else if (typeof value === 'object' && value !== null) {
        console.log(`  ${key}: Object with keys:`, Object.keys(value));
      }
    });
  });
}

// Call this function after the software dashboard loads
// inspectAgentData();
