Import-Module AWS.Tools.EC2

#CCP
$url = "flo-ccp.io"
$appid = "CCP1"
$safe = "AWS-IAM"
$object = "s3put"

#Get AWS secret
$response = Invoke-RestMethod -SkipCertificateCheck -Uri "https://$url/AIMWebService/api/Accounts?AppID=$appid&Safe=$safe&Object=$object"

#Set PVWA
$PVWAAddress  = "https://flolab.privilegecloud.cyberark.com/"

###Needs Work
##-CREATE ROLE BASED ACCOUNT OTHER THAN BUILT-IN ADMIN
$object="cybr-flo"
$safe="CYBR-INTERNAL"
#-Get BUILT-IN ADMIN for PVWA REST automation
$restResponse = Invoke-RestMethod -SkipCertificateCheck -Uri "https://$url/AIMWebService/api/Accounts?AppID=$appid&Safe=$safe&Object=$object"

$restUsername = $restResponse.UserName
$restPassword = $restResponse.Content
$securePassword = ConvertTo-SecureString -String $restPassword -AsPlainText -Force
$restCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $restUsername, $securePassword

#AWS Creds
$secretkey = $response.Content
$accesskey = $response.AWSAccessKeyID
Set-AWSCredential -AccessKey $accesskey -SecretKey $secretkey

###Needs Work
##-Request and pass quantity & region
##-AMI refers to policy ID (unixssh=ami-1234, windows=ami-9876, etc.)
##-Keyname generated, passed and uploaded into PVWA
$r="us-east-2"
$q=2
$ami="ami-09558250a3419e7d0"
$keyname="flo-home-lab"

#Create the image(s)
#New-EC2Instance -ImageId $ami -MinCount $q -MaxCount $q -InstanceType t2.micro -KeyName $keyname -Region $r

(Get-EC2Instance).Instances | Select-Object PublicIpAddress
#Get-EC2InstanceAttribute -InstanceId "i-00c84139df1397d70" -Attribute "Public IPv4 address"

# # #Logon PVWA REST
# New-PASSession -Credential $restCredential -BaseURI $PVWAAddress

# ###Needs Work
# ##-Grabbing priv key from local file system
# $privKey = Get-Content ("M:\data\priv\flo-home-lab.pem")
# Write-Host $privKey
# $privKey = ConvertTo-SecureString -String $privKey -AsPlainText -Force

# #Define Safe
# $SafeName = "nix"

# For ($i=0; $i -lt $q; $i++) {
       
#     #Add Account
#     $TGT_User     = "ec2-user"
#     $TGT_Address  = "10.0.0.0"
#     $TGT_Platform = "AML2-EC2-Flolab-Keys"
#     Add-PASAccount -secretType Key -secret $privKey -SafeName $SafeName -PlatformID $TGT_Platform -Address $TGT_Address -Username $TGT_User -platformAccountProperties $platformAccountProperties
# }