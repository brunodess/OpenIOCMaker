##########################################################################################################################################################
### Create IOC File from list of hashes to use on Trend Micro Endpoint Sensor
### Input List must be only the hash values
### This script only creates entry for SHA 1 and MD5, other hashes are not supported
### 
### INSTRUCTIONS
### Input the hash list file path below, on the Set file Parameters section, inputFilePath String Variable
### Input the output IOC file path below, on the Set file Parameters section, outputFilePath String Variable
### Input the output IOC file name below, on the Set file Parameters section, outputFileName String Variable
###
### the XMLTemplate variable can be uncommented and should point to the correct IOC XML file to be populated with the hashes
#### or, leave it commented out to use the default hard coded XML Template
###
##########################################################################################################################################################

#Set file Parameters
$outputFilePath = ""
$outputFileName = "IOC-$(New-Guid).xml"
$inputFilePath = ""
$XMLTemplate = $null

# Uncomment the line below to load custom XML template. Leave the line above untouched, it clears the variable if running the Script from IDE
#$XMLTemplate = ""

##########################################################################################################################################################
### Default XML Template Builder, if Variable XML Template is not set, use Default hard coded Template
if ( $XMLTemplate -eq $null ) { # XML Builder IF BEGIN
    $XMLTemplate = @'
<?xml version="1.0" encoding="us-ascii"?>
    <ioc xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns="http://schemas.mandiant.com/2010/ioc">
        
        <links />
        <definition>
            <Indicator>
                <IndicatorItem>
                    <Context type="mir" />
                    <Content type="string">a4385ad1aca1eb90a2f7688515f7a2fa6f4b5d01</Content>
                </IndicatorItem>
            </Indicator>
        </definition>
    </ioc>
'@    
    
    [xml]$InputXML = $XMLTemplate

    $InputXML.ioc.SetAttribute('id',$(New-Guid))
    $InputXML.ioc.SetAttribute('last-modified',$(Get-Date -UFormat "%Y-%m-%dT%T"))    

    $InputXML.ioc.definition.Indicator.SetAttribute('id',$(New-Guid))
    $InputXML.ioc.definition.Indicator.SetAttribute('operator','OR') #### It's possible to use AND operator as well
    $InputXML.ioc.definition.Indicator.RemoveChild($InputXML.ioc.definition.Indicator.IndicatorItem)

    $XMLDescription = $InputXML.CreateElement("short_description",$InputXML.ioc.NamespaceURI)
    $XMLDescription.InnerText = $outputFileName
    $XMLAuthor = $InputXML.CreateElement("authored_by",$InputXML.ioc.NamespaceURI)
    $XMLAuthor.InnerText = $env:UserName
    $XMLDate = $InputXML.CreateElement("authored_date",$InputXML.ioc.NamespaceURI)
    $XMLDate.InnerText = Get-Date -UFormat "%Y-%m-%dT%T"
    $InputXML.ioc.PrependChild($XMLDate)
    $InputXML.ioc.PrependChild($XMLAuthor)    
    $InputXML.ioc.PrependChild($XMLDescription)
    
    

} else {
    #Load XML Template from file to PS Object
    [xml]$InputXML = Get-Content $XMLTemplate

} # XML Builder IF END

##########################################################################################################################################################

#Load hash list from file
$hashList = Get-Content $inputFilePath

#hash List ForEach loop, to populate the XML with each hash
$counter = 0
foreach ($hash in $hashList){ #hash List Iteration BEGIN
    
    $FileItem = ''

    #Check hash length $hash.Length -- $hashList[0].Length
    if ($hash.Length -eq 40) { #Hash has correct length for SHA 1
        $FileItem = 'FileItem/Sha1sum'
        
    } elseif ($hash.Length -eq 32) { #Hash has correct length for MD5
        $FileItem = 'FileItem/md5sum'
    } else { #Hash has an unsupported length for this script (SHA 256, maybe)
        echo "Invalid or unsupported hash detected on position $counter"
        break
    }
    $counter++

    #Clear handlers for the XML
    $NewItem = $null
    $NewContent = $null
    $NewContext = $null
    
    #Create blank XML elements do Append
    $NewItem = $InputXML.CreateElement("IndicatorItem",$InputXML.ioc.NamespaceURI)
    $NewContent = $InputXML.CreateElement("Content",$InputXML.ioc.NamespaceURI)
    $NewContext = $InputXML.CreateElement("Context",$InputXML.ioc.NamespaceURI)

    #Set attributes of element wrapper (IndicatorItem)
    $NewItem.SetAttribute('id',$(New-Guid))
    $NewItem.SetAttribute('condition','is')

    #Set Attributes of Context Child Item
    $NewContext.SetAttribute('document','FileItem')
    $NewContext.SetAttribute('search',$FileItem)
    $NewContext.SetAttribute('type','mir')
    
    #Set Attribute and text of Content Item (This is the hash value)
    $NewContent.SetAttribute('type','string')
    $NewContent.InnerText = $hash

    #Append child elements to wrapper Item (IndicatorItem)
    $NewItem.AppendChild($NewContext)
    $NewItem.AppendChild($NewContent)

    #Append IndicatorItem to main XML
    $InputXML.ioc.definition.Indicator.AppendChild($NewItem)

} #hash List Iteration END

echo "Hashes loaded: $counter"
echo "IndicatorItem nodes on the XML: $($InputXML.ioc.definition.Indicator.IndicatorItem.Count)"
$InputXML.Save($outputFilePath+$outputFileName)
##########################################################################################################################################################
