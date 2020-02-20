Sub Dummy()
Set XML = CreateObject("Microsoft.XMLDOM")
XML.async = False
Set xsl = XML
xsl.Load "xml.xml"
XML.transformNode xsl
End Sub
Dummy()
