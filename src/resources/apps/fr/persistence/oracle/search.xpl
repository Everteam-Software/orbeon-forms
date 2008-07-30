<?xml version="1.0" encoding="utf-8"?>
<!--
    Copyright (C) 2008 Orbeon, Inc.

    This program is free software; you can redistribute it and/or modify it under the terms of the
    GNU Lesser General Public License as published by the Free Software Foundation; either version
    2.1 of the License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
    without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
    See the GNU Lesser General Public License for more details.

    The full text of the license is available at http://www.gnu.org/copyleft/lesser.html
-->
<p:config xmlns:p="http://www.orbeon.com/oxf/pipeline"
        xmlns:sql="http://orbeon.org/oxf/xml/sql"
        xmlns:odt="http://orbeon.org/oxf/xml/datatypes"
        xmlns:xs="http://www.w3.org/2001/XMLSchema"
        xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
        xmlns:saxon="http://saxon.sf.net/"
        xmlns:oxf="http://www.orbeon.com/oxf/processors"
        xmlns:xi="http://www.w3.org/2001/XInclude"
        xmlns:xforms="http://www.w3.org/2002/xforms"
        xmlns:xxforms="http://orbeon.org/oxf/xml/xforms"
        xmlns:ev="http://www.w3.org/2001/xml-events"
        xmlns:pipeline="java:org.orbeon.oxf.processor.pipeline.PipelineFunctionLibrary">

    <!--
        Search instance, e.g.:

        <search>
            <app>orbeon</app>
            <form>bookcast</form>
            <query>free</query>
            <query name="title" path="details/title" type="xs:string" control="input">title</query>
            <query name="author" path="details/author" type="xs:string" control="input">author</query>
            <query name="language" path="details/language" type="xs:string" control="select1">en</query>
            <page-size>5</page-size>
            <page-number>1</page-number>
            <sort-key/>
            <lang>en</lang>
        </search>
    -->
    <p:param name="instance" type="input" debug="search instance"/>

    <!--
        Search result, e.g.:

        <documents total="2" search-total="2" page-size="5" page-number="1" query="">
            <document created="2008-07-28T18:43:59.363-07:00" last-modified="2008-07-28T18:43:59.363-07:00" name="329737EA7637FAC1BC8FD6139BDFAE97" offline="">
                <details>
                    <detail>a</detail>
                    <detail>aa</detail>
                    <detail/>
                </details>
            </document>
            <document created="2008-07-25T17:31:19.016-07:00" last-modified="2008-07-25T17:34:33.503-07:00" name="C7AEA87DA2CC07680D97BC28A87EBAF5" offline="">
                <details>
                    <detail>ab</detail>
                    <detail>ba</detail>
                    <detail/>
                </details>
            </document>
        </documents>
    -->
    <p:param name="data" type="output" debug="search result"/>

    <!-- Run query -->
    <p:processor name="oxf:sql">
        <p:input name="data" href="#instance"/>
        <p:input name="config" transform="oxf:unsafe-xslt" href="#instance">
            <sql:config xsl:version="2.0">
                <documents>
                    <sql:connection>
                        <sql:datasource>
                            <xsl:value-of select="pipeline:property('oxf.fr.persistence.service.oracle.datasource')"/>
                        </sql:datasource>

                        <!-- Query that returns all the search results, which we will reuse in multiple palces -->
                        <xsl:variable name="query">
                            select created, last_modified, document_id
                                <!-- Go over detail columns and extract data from XML -->
                                <xsl:for-each select="/search/query[@path]">
                                    , extractValue(xml, '/*/<xsl:value-of select="@path"/>') detail_<xsl:value-of select="position()"/>
                                </xsl:for-each>
                            from orbeon_form_data
                            where app = <sql:param type="xs:string" select="/search/app"/>
                                and form = <sql:param type="xs:string" select="/search/form"/>
                                <xsl:for-each select="/search/query[@path and . != '']">
                                    and lower(extractValue(xml, '/*/<xsl:value-of select="@path"/>')) like '%<xsl:value-of select="lower-case(replace(., '''', ''''''))"/>%'
                                </xsl:for-each>
                            order by created
                        </xsl:variable>

                        <!-- Get total number of document in collection for this app/form -->
                        <sql:execute>
                            <sql:query>
                                select
                                    (select count(*) from orbeon_form_data
                                        where app = <sql:param type="xs:string" select="/search/app"/>
                                        and form = <sql:param type="xs:string" select="/search/form"/>) total,
                                    (select count(*) from (<xsl:copy-of select="$query"/>)) search_total
                                from dual
                            </sql:query>
                            <sql:result-set>
                                <sql:row-iterator>
                                    <sql:get-columns format="xml"/>
                                </sql:row-iterator>
                            </sql:result-set>
                        </sql:execute>

                        <!-- Get details -->
                        <sql:execute>
                            <sql:query>
                                select *
                                  from ( select
                                  a.*, ROWNUM rnum
                                      from ( <xsl:copy-of select="$query"/> ) a
                                      where ROWNUM &lt;= <xsl:value-of select="/search/page-number * /search/page-size"/> )
                                where rnum  > <xsl:value-of select="(/search/page-number - 1) * /search/page-size"/>
                            </sql:query>
                            <sql:result-set>
                                <sql:row-iterator>
                                    <document>
                                        <created><sql:get-column-value column="created"/></created>
                                        <last-modified><sql:get-column-value column="last_modified"/></last-modified>
                                        <document-id><sql:get-column-value column="document_id"/></document-id>
                                        <xsl:for-each select="/search/query[@path]">
                                            <detail><sql:get-column-value column="detail_{position()}"/></detail>
                                        </xsl:for-each>
                                    </document>
                                </sql:row-iterator>
                            </sql:result-set>
                        </sql:execute>
                    </sql:connection>
                </documents>
            </sql:config>
        </p:input>
        <p:output name="data" id="sql-output" debug="sql-output"/>
    </p:processor>

    <!-- Transform output from SQL processor into the XML form the caller expects -->
    <p:processor name="oxf:xslt">
        <p:input name="data" href="#sql-output"/>
        <p:input name="config">
            <xsl:stylesheet version="2.0">
                <xsl:import href="oxf:/oxf/xslt/utils/copy.xsl"/>

                <!-- Move total and search-total as attribute -->
                <xsl:template match="documents">
                    <documents total="{total}" search-total="{search-total}">
                        <xsl:apply-templates select="document"/>
                    </documents>
                </xsl:template>

                <!-- Move created, last-modified, and name as attributes -->
                <!-- Add wrapping details element -->
                <xsl:template match="document">
                    <document created="{created}" last-modified="{last-modified}" name="{document-id}">
                        <details>
                            <xsl:for-each select="detail">
                                <detail>
                                    <xsl:value-of select="."/>
                                </detail>
                            </xsl:for-each>
                        </details>
                    </document>
                </xsl:template>

            </xsl:stylesheet>
        </p:input>
        <p:output name="data" ref="data"/>
    </p:processor>


</p:config>