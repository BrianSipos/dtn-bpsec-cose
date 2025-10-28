<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:template match="tt" />
  <!-- Leave out some artworks -->
  <xsl:template match="sourcecode[@type='pem']" />
  <xsl:template match="sourcecode[@type='x509dump']" />
  <xsl:template match="sourcecode[@type='cbor']" />
  <xsl:template match="sourcecode[@type='cborseq']" />
  <xsl:template match="sourcecode[@type='cborhex']" />
  <xsl:template match="sourcecode[@type='cddl']" />
  <!-- standard copy template -->
  <xsl:template match="@*|node()">
    <xsl:copy>
      <xsl:apply-templates select="@*" />
      <xsl:apply-templates />
    </xsl:copy>
  </xsl:template>
</xsl:stylesheet>
