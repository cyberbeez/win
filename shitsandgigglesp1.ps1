# Step 1: Install the Network Load Balancing feature (if not already installed)
Install-WindowsFeature -Name NLB -IncludeManagementTools

# Step 2: Define the cluster parameters
$ClusterName = "NLB-Cluster"  # Name for the NLB Cluster
$ClusterIP = "192.168.1.100"  # Virtual IP Address for the cluster (Use a valid IP in your network)
$SubnetMask = "255.255.255.0"  # Subnet mask
$Affinity = "Single"          # Affinity setting: "None" or "Single"
$LoadWeight = 100             # Load balancing weight (default: 100)

# Step 3: Configure NLB on each node (Server 1 & Server 2)
$Node1IP = "192.168.1.101"    # IP address of the first NLB node (replace with your server's IP)
$Node2IP = "192.168.1.102"    # IP address of the second NLB node (replace with your server's IP)

# Configure NLB cluster on Server 1
New-NlbCluster -InterfaceName (Get-NetAdapter | Where-Object {$_.IPAddress -eq $Node1IP}).Name -ClusterIPAddress $ClusterIP -SubnetMask $SubnetMask -ClusterName $ClusterName -Affinity $Affinity -LoadWeight $LoadWeight

# Add Server 2 to the NLB cluster
Add-NlbClusterNode -InterfaceName (Get-NetAdapter | Where-Object {$_.IPAddress -eq $Node2IP}).Name -ClusterName $ClusterName

# Step 4: Verify the NLB cluster configuration
Get-NlbCluster -ClusterName $ClusterName
Get-NlbClusterNode -ClusterName $ClusterName

# Step 5: Start NLB service if it is not already running
Start-Service -Name "nlb"

# Step 6: Verify the NLB status on both nodes
Get-NetIPAddress | Where-Object {$_.IPAddress -eq $ClusterIP}

# Step 7: (Optional) Start the NLB Cluster
Start-NlbCluster -ClusterName $ClusterName

Write-Host "Network Load Balancing configuration completed successfully!"
