<?xml version="1.0" encoding="UTF-8"?>
<!--
    Copyright (C) 2009 Orbeon, Inc.
    
    This program is free software; you can redistribute it and/or modify it under the terms of the
    GNU Lesser General Public License as published by the Free Software Foundation; either version
    2.1 of the License, or (at your option) any later version.
    
    This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
    without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
    See the GNU Lesser General Public License for more details.
    
    The full text of the license is available at http://www.gnu.org/copyleft/lesser.html
-->
<xsl:transform xmlns:xforms="http://www.w3.org/2002/xforms"
    xmlns:xhtml="http://www.w3.org/1999/xhtml" xmlns:xxforms="http://orbeon.org/oxf/xml/xforms"
    xmlns:ev="http://www.w3.org/2001/xml-events" xmlns:xs="http://www.w3.org/2001/XMLSchema"
    xmlns:xbl="http://www.w3.org/ns/xbl" xmlns:xxbl="http://orbeon.org/oxf/xml/xbl"
    xmlns:fr="http://orbeon.org/oxf/xml/form-runner"
    xmlns:oxf="http://www.orbeon.com/oxf/processors" xmlns:exf="http://www.exforms.org/exf/1-0"
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="2.0">

    <xsl:variable name="parameters">
        <!-- These optional attributes are used as parameters -->
        <parameter>appearance</parameter>
        <parameter>scrollable</parameter>
        <parameter>width</parameter>
        <parameter>height</parameter>
        <parameter>paginated</parameter>
        <parameter>rowsPerPage</parameter>
        <parameter>innerTableWidth</parameter>
        <parameter>loading</parameter>
    </xsl:variable>

    <xsl:variable name="numberTypes">
        <type>xs:decimal</type>
        <type>xs:integer</type>
        <type>xs:nonPositiveInteger</type>
        <type>xs:negativeInteger</type>
        <type>xs:long</type>
        <type>xs:int</type>
        <type>xs:short</type>
        <type>xs:byte</type>
        <type>xs:nonNegativeInteger</type>
        <type>xs:unsignedLong</type>
        <type>xs:unsignedInt</type>
        <type>xs:unsignedShort</type>
        <type>xs:unsignedByte</type>
        <type>xs:positiveInteger</type>
    </xsl:variable>
    <xsl:variable name="numberTypesEnumeration">
        <xsl:for-each select="$numberTypes/*">
            <xsl:if test="position() >1">,</xsl:if>
            <xsl:text>resolve-QName('</xsl:text>
            <xsl:value-of select="."/>
            <xsl:text>',..)</xsl:text>
        </xsl:for-each>
    </xsl:variable>


    <!-- Set some variables that will dictate the geometry of the widget -->
    <xsl:variable name="scrollH" select="/*/@scrollable = ('horizontal', 'both') and /*/@width"/>
    <xsl:variable name="scrollV" select="/*/@scrollable = ('vertical', 'both') and /*/@height"/>
    <xsl:variable name="height"
        select="if ($scrollV) then concat('height: ', /*/@height, ';') else ''"/>
    <xsl:variable name="width"
        select="if (/*/@width) then concat('width: ', /*/@width, ';') else ''"/>
    <xsl:variable name="id" select="if (/*/@id) then /*/@id else generate-id(/*)"/>
    <xsl:variable name="paginated" select="/*/@paginated = 'true'"/>
    <xsl:variable name="rowsPerPage"
        select="if (/*/@rowsPerPage castable as xs:integer) then /*/@rowsPerPage cast as xs:integer else 10"/>
    <xsl:variable name="innerTableWidth"
        select="if (/*/@innerTableWidth) then concat(&quot;'&quot;, /*/@innerTableWidth, &quot;'&quot;) else 'null'"/>
    <xsl:variable name="hasLoadingFeature" select="count(/*/@loading) = 1"/>

    <xsl:template match="@*|node()" mode="#all">
        <!-- Default template == identity -->
        <xsl:copy>
            <xsl:apply-templates select="@*|node()" mode="#current"/>
        </xsl:copy>
    </xsl:template>

    <xsl:template match="/*">
        <!-- Matches the bound element -->

        <xsl:if test="not(xhtml:thead)">
            <xsl:message terminate="yes">Datatable components should include a thead
                element.</xsl:message>
        </xsl:if>
        <xsl:if test="not(xhtml:tbody)">
            <xsl:message terminate="yes">Datatable components should include a tbody
                element.</xsl:message>
        </xsl:if>

        <xsl:variable name="columns">
            <xsl:apply-templates select="xhtml:thead/xhtml:tr[1]/*" mode="columns"/>
        </xsl:variable>

        <xhtml:div id="{$id}-container">
            <xsl:copy-of select="namespace::*"/>

            <xforms:model id="datatable-model">
                <xforms:instance id="datatable-instance">
                    <columns xmlns="" currentSortColumn="-1">
                        <xsl:for-each select="$columns/*">
                            <xsl:copy>
                                <xsl:attribute name="nbColumns"/>
                                <xsl:attribute name="index"/>
                                <xsl:attribute name="currentSortOrder"/>
                                <xsl:attribute name="nextSortOrder"/>
                                <xsl:attribute name="type"/>
                                <xsl:attribute name="pathToFirstNode"/>
                                <xsl:copy-of select="@*"/>
                            </xsl:copy>
                        </xsl:for-each>
                    </columns>
                </xforms:instance>
                <xforms:bind nodeset="column/@nbColumns" calculate="1"/>
                <xforms:bind nodeset="columnSet/@nbColumns" calculate="count(../column)"/>
                <xforms:bind nodeset="*/@index" calculate="count(../preceding::column) + 1"/>
                <xforms:bind nodeset="//column/@currentSortOrder"
                    calculate="if (../@index = /*/@currentSortColumn) then . else 'none'"/>
                <xforms:bind nodeset="//column/@nextSortOrder"
                    calculate="if (../@index = /*/@currentSortColumn) then if (../@currentSortOrder = 'ascending') then 'descending' else 'ascending' else 'ascending'"/>
                <xforms:bind nodeset="//column/@pathToFirstNode"
                    calculate="concat('xxforms:component-context()/({/*/xhtml:tbody/xforms:repeat/@nodeset})[1]/(', ../@sortKey, ')')"/>
                <xforms:bind nodeset="//column[@fr:sortType]/@type" calculate="../@fr:sortType"/>
                <xforms:bind nodeset="//column[not(@fr:sortType)]/@type"
                    calculate="for $value in xxforms:evaluate(../@pathToFirstNode)
                        return if ($value instance of node())
                        then if (xxforms:type($value) = ({$numberTypesEnumeration}))
                            then 'number'
                            else 'text'
                        else if ($value instance of xs:decimal)
                            then 'number'
                            else 'text'"
                />
            </xforms:model>

            <xxforms:variable name="currentSortOrder" model="datatable-model"
                select="instance('datatable-instance')/@currentSortOrder"/>
            <xxforms:variable name="currentSortColumn" model="datatable-model"
                select="instance('datatable-instance')/@currentSortColumn"/>


            <xhtml:div style="border:thin solid black">
                <xhtml:h3>Local instance:</xhtml:h3>
                <xforms:group model="datatable-model" instance="datatable-instance">
                    <xhtml:p>columns</xhtml:p>
                    <xhtml:ul>
                        <xforms:repeat nodeset="@*">
                            <xhtml:li>
                                <xforms:output ref=".">
                                    <xforms:label>
                                        <xforms:output value="concat(name(), ': ')"/>
                                    </xforms:label>
                                </xforms:output>
                            </xhtml:li>
                        </xforms:repeat>
                    </xhtml:ul>
                    <xforms:repeat nodeset="*|//column">
                        <xhtml:p>
                            <xforms:output value="name()"/>
                        </xhtml:p>
                        <xhtml:ul>
                            <xforms:repeat nodeset="@*">
                                <xhtml:li>
                                    <xforms:output ref=".">
                                        <xforms:label>
                                            <xforms:output value="concat(name(), ': ')"/>
                                        </xforms:label>
                                    </xforms:output>
                                </xhtml:li>
                            </xforms:repeat>
                        </xhtml:ul>
                    </xforms:repeat>
                </xforms:group>
            </xhtml:div>

            <xsl:if test="$hasLoadingFeature">
                <xxforms:variable name="loading" xbl:attr="select=loading"/>
            </xsl:if>

            <xforms:group>
                <xsl:attribute name="ref">
                    <xsl:text>xxforms:component-context()</xsl:text>
                    <xsl:if test="$hasLoadingFeature">[not($loading = true())]</xsl:if>
                </xsl:attribute>

                <xforms:action ev:event="xforms-enabled">
                    <xxforms:script> YAHOO.log("Enabling datatable id <xsl:value-of select="$id"
                        />","info"); ORBEON.widgets.datatable.init(this, <xsl:value-of
                            select="$innerTableWidth"/>); </xxforms:script>
                </xforms:action>

                <xhtml:table id="{$id}-table"
                    class="datatable datatable-{$id} yui-dt-table {if ($scrollV) then 'fr-scrollV' else ''}  {if ($scrollH) then 'fr-scrollH' else ''} "
                    style="{$height} {$width}">
                    <!-- Copy attributes that are not parameters! -->
                    <xsl:apply-templates select="@*[not(name() = ($parameters/*, 'id' ))]"/>
                    <xhtml:thead id="{$id}-thead">
                        <xhtml:tr class="yui-dt-first yui-dt-last {@class}" id="{$id}-thead-tr">
                            <xsl:apply-templates select="$columns/*"/>
                        </xhtml:tr>
                    </xhtml:thead>
                    <xsl:apply-templates select="xhtml:tbody"/>
                </xhtml:table>

            </xforms:group>

            <xsl:if test="$hasLoadingFeature">
                <xforms:group ref="xxforms:component-context()[$loading = true()]">
                    <xhtml:span class="yui-dt yui-dt-scrollable" style="display: table; ">
                        <xhtml:span class="yui-dt-hd"
                            style="border: 1px solid rgb(127, 127, 127); display: table-cell;">
                            <xhtml:table class="datatable  yui-dt-table" style="{$height} {$width}">
                                <xhtml:thead>
                                    <xhtml:tr class="yui-dt-first yui-dt-last">
                                        <xsl:apply-templates select="$columns/*"
                                            mode="loadingIndicator"/>
                                    </xhtml:tr>
                                </xhtml:thead>
                                <xhtml:tbody>
                                    <xhtml:tr>
                                        <xhtml:td colspan="{count($columns/*)}"
                                            class="fr-datatable-is-loading"/>
                                    </xhtml:tr>
                                </xhtml:tbody>
                            </xhtml:table>
                        </xhtml:span>
                    </xhtml:span>
                </xforms:group>
            </xsl:if>


        </xhtml:div>
        <!-- End of template on the bound element -->
    </xsl:template>


    <!-- <xsl:template match="/*/xhtml:thead/xhtml:tr">
        <xhtml:tr class="yui-dt-first yui-dt-last {@class}" id="{$id}-thead-tr">
            <xsl:apply-templates select="@*[not(name() = ('class', 'id') )]|node()"/>
        </xhtml:tr>
    </xsl:template>

    <xsl:template match="/*/xhtml:thead">
        <xhtml:thead id="{$id}-thead">
            <xsl:apply-templates select="@*[not(name() = ('id') )]|node()"/>
        </xhtml:thead>
    </xsl:template>-->

    <xsl:template name="header-cell">

        <!-- XXForms variable "columnDesc" is the current column description when we enter here -->

        <!-- <xforms:output value="$columnDesc/@index"/>-->

        <xhtml:div class="yui-dt-resizerliner">
            <xhtml:div class="yui-dt-liner">
                <xhtml:span class="yui-dt-label">
                    <xsl:choose>
                        <xsl:when test="@fr:sortable = 'true'">
                            <xforms:trigger appearance="minimal">
                                <xforms:label>
                                    <xsl:apply-templates select="node()"/>
                                </xforms:label>
                                <xforms:hint>Click to sort <xforms:output
                                        value="$columnDesc/@nextSortOrder"/></xforms:hint>
                                <xforms:action ev:event="DOMActivate">
                                    <xforms:setvalue ref="$columnDesc/@currentSortOrder"
                                        value="$columnDesc/@nextSortOrder"/>
                                    <xforms:setvalue ref="$currentSortColumn"
                                        value="$columnDesc/@index"/>
                                </xforms:action>
                            </xforms:trigger>
                        </xsl:when>
                        <xsl:otherwise>
                            <xsl:apply-templates select="node()"/>
                        </xsl:otherwise>
                    </xsl:choose>
                </xhtml:span>
            </xhtml:div>
            <xsl:if test="@fr:resizeable = 'true'">
                <xhtml:div id="{generate-id()}" class="yui-dt-resizer"
                    style=" left: auto; right: 0pt; top: auto; bottom: 0pt; height: 100%;"/>
            </xsl:if>
        </xhtml:div>

    </xsl:template>

    <xsl:template match="column|columnSet" priority="1">
        <xsl:apply-templates select="header"/>
    </xsl:template>

    <xsl:template match="header">
        <xsl:apply-templates select="*"/>
    </xsl:template>

    <xsl:template match="header/xhtml:th">
        <xhtml:th
            class="
            {if (@fr:sortable = 'true') then 'yui-dt-sortable' else ''} 
            {if (@fr:resizeable = 'true') then 'yui-dt-resizeable' else ''} 
             {@class}
            ">
            <xsl:apply-templates select="@*[name() != 'class']"/>
            <xxforms:variable name="index" select="{count(../../preceding-sibling::*) + 1}"/>
            <xxforms:variable name="columnDesc" model="datatable-model"
                select="instance('datatable-instance')/*[position() = $index]"/>
            <xsl:call-template name="header-cell"/>

        </xhtml:th>
    </xsl:template>

    <xsl:template match="header/xforms:repeat/xhtml:th">
        <xhtml:th
            class="
            {if (@fr:sortable = 'true') then 'yui-dt-sortable' else ''} 
            {if (@fr:resizeable = 'true') then 'yui-dt-resizeable' else ''} 
            {@class}
            ">
            <xsl:apply-templates select="@*[name() != 'class']"/>
            <xxforms:variable name="position" select="position()"/>
            <xxforms:variable name="index" select="{count(../../../preceding-sibling::*) + 1}"/>
            <xxforms:variable name="columnSet" model="datatable-model"
                select="instance('datatable-instance')/*[position() = $index]"/>
            <xforms:group ref=".">
                <xforms:action ev:event="xforms-enabled">
                    <!--<xforms:delete nodeset="$columnSet/column[@position = $position]"/>-->
                    <xforms:insert context="$columnSet" nodeset="column"
                        origin="xxforms:element('column', (
                                xxforms:attribute('position', $position),
                                xxforms:attribute('nbColumns', 1),
                                xxforms:attribute('index', $columnSet/@index + $position - 1),
                                xxforms:attribute('sortKey', concat( '(',  $columnSet/@nodeset, ')[', $position , ']/', $columnSet/@sortKey)),
                                xxforms:attribute('currentSortOrder', ''),
                                xxforms:attribute('nextSortOrder', ''),
                                xxforms:attribute('type', ''),
                                xxforms:attribute('pathToFirstNode', ''),
                                $columnSet/@fr:sortable,
                                $columnSet/@fr:resizeable,
                                $columnSet/@fr:sortType
                                ))"
                        if="not($columnSet/column[@position = $position])
                           "
                    />
                </xforms:action>
            </xforms:group>

            <xxforms:variable name="columnDesc" select="$columnSet/column[@position = $position]"/>

            <xsl:call-template name="header-cell"/>

        </xhtml:th>
    </xsl:template>

    <xsl:template match="/*/xhtml:tbody">
        <xhtml:tbody class="yui-dt-data {@class}" id="{$id}-tbody">
            <xsl:apply-templates select="@*[not(name() = ('class', 'id'))]|node()"/>
        </xhtml:tbody>
    </xsl:template>

    <xsl:template match="/*/xhtml:tbody/xforms:repeat">
        <xxforms:variable name="currentSortColumnIndex" model="datatable-model"
            select="@currentSortColumn"/>
        <xxforms:variable name="currentSortColumn" model="datatable-model"
            select="(//column)[@index=$currentSortColumnIndex]"/>
        <xforms:repeat>
            <xsl:attribute name="nodeset">
                <xsl:if test="$paginated">(</xsl:if>
                <xsl:text>if (not($currentSortColumn) or $currentSortColumn/@currentSortOrder = 'none') then </xsl:text>
                <xsl:value-of select="@nodeset"/>
                <xsl:text> else exf:sort(</xsl:text>
                <xsl:value-of select="@nodeset"/>
                <xsl:text>, $currentSortColumn/@sortKey , $currentSortColumn/@type, $currentSortColumn/@currentSortOrder)</xsl:text>
                <xsl:if test="$paginated">)[position() >= ($page - 1) * <xsl:value-of
                        select="$rowsPerPage"/> + 1 and position() &lt;= $page * <xsl:value-of
                        select="$rowsPerPage"/>]</xsl:if>
            </xsl:attribute>
            <xsl:apply-templates select="@*[not(name()='nodeset')]|node()"/>
        </xforms:repeat>
    </xsl:template>

    <xsl:template match="/*/xhtml:tbody/xforms:repeat/xhtml:tr">
        <xhtml:tr
            class="
            {{if (position() = 1) then 'yui-dt-first' else '' }}
            {{if (position() = last()) then 'yui-dt-last' else '' }}
            {{if (position() mod 2 = 0) then 'yui-dt-odd' else 'yui-dt-even' }}
            {{if (xxforms:index() = position()) then 'yui-dt-selected' else ''}}
            {@class}"
            style="height: auto;">
            <xsl:apply-templates select="@*[name() != 'class']|node()"/>
        </xhtml:tr>
    </xsl:template>

    <xsl:template match="/*/xhtml:tbody/xforms:repeat/xhtml:tr/xhtml:td">
        <xsl:variable name="position" select="count(preceding-sibling::xhtml:td) + 1"/>
        <xxforms:variable name="currentId" model="datatable-model" select="@currentId"/>
        <xxforms:variable name="currentOrder" model="datatable-model" select="@currentOrder"/>
        <xhtml:td
            class="
            {if (@fr:sortable = 'true') then 'yui-dt-sortable' else ''} 
            {{if ({$position} = $currentId) 
                then  if($currentOrder = 'descending') then 'yui-dt-desc' else 'yui-dt-asc'
                else ''}}
            {@class}            
            ">

            <xsl:apply-templates select="@*[name() != 'class']"/>
            <xhtml:div class="yui-dt-liner">
                <xsl:apply-templates select="node()"/>
            </xhtml:div>
        </xhtml:td>
    </xsl:template>

    <xsl:template match="@fr:*"/>

    <!-- 
        
        sortKey mode builds a list of sort keys from a cell content 
        
        Note that we don't bother to take text nodes into account, assuming that
        they are constant and should not influence the sort order...
        
    -->

    <xsl:template match="*" mode="sortKey" priority="-0.25">
        <xsl:apply-templates select="*" mode="sortKey"/>
    </xsl:template>

    <xsl:template match="xforms:output" mode="sortKey">
        <xpath>
            <xsl:value-of select="@ref|@value"/>
        </xpath>
    </xsl:template>


    <!-- 

        Column mode is used to consolidate information about columns
        from theader and tbody

    -->

    <xsl:template match="/*/xhtml:thead/xhtml:tr/*" mode="columns">
        <xsl:message terminate="yes">Unxepected element (<xsl:value-of select="name()"/> found in a
            datatable header (expecting either xhtml:th or xforms:repeat).</xsl:message>
    </xsl:template>

    <xsl:template match="/*/xhtml:thead/xhtml:tr/xhtml:th" mode="columns" priority="1">
        <xsl:variable name="position" select="count(preceding-sibling::*) + 1"/>
        <xsl:variable name="body"
            select="/*/xhtml:tbody/xforms:repeat/xhtml:tr/*[position() = $position]"/>
        <xsl:if test="not($body/self::xhtml:td)">
            <xsl:message terminate="yes">Datatable: mismatch, element position <xsl:value-of
                    select="$position"/> is a <xsl:value-of select="name()"/> in the header and a
                    <xsl:value-of select="name($body)"/> in the body.</xsl:message>repeat </xsl:if>
        <xsl:variable name="sortKey">
            <xsl:apply-templates select="$body" mode="sortKey"/>
        </xsl:variable>
        <column sortKey="{$sortKey}" type="" xmlns="">
            <xsl:copy-of select="@*"/>
            <header>
                <xsl:copy-of select="."/>
            </header>
            <body>
                <xsl:copy-of select="$body"/>
            </body>
        </column>
    </xsl:template>

    <xsl:template match="/*/xhtml:thead/xhtml:tr/xforms:repeat" mode="columns" priority="1">
        <xsl:variable name="position" select="count(preceding-sibling::*) + 1"/>
        <xsl:variable name="body"
            select="/*/xhtml:tbody/xforms:repeat/xhtml:tr/*[position() = $position]"/>
        <xsl:if test="not($body/self::xforms:repeat)">
            <xsl:message terminate="yes">Datatable: mismatch, element position <xsl:value-of
                    select="$position"/> is a <xsl:value-of select="name()"/> in the header and a
                    <xsl:value-of select="name($body)"/> in the body.</xsl:message>
        </xsl:if>
        <xsl:variable name="sortKey">
            <xsl:apply-templates select="$body" mode="sortKey"/>
        </xsl:variable>
        <columnSet sortKey="{$sortKey}" xmlns="">
            <xsl:copy-of select="$body/@nodeset|xhtml:th/@*"/>
            <header>
                <xsl:copy-of select="."/>
            </header>
            <body>
                <xsl:copy-of select="$body"/>
            </body>
        </columnSet>
    </xsl:template>

    <xsl:template match="column" mode="loadingIndicator">
        <xsl:apply-templates select="header/xhtml:th"/>
    </xsl:template>

    <xsl:variable name="fakeColumn">
        <header xmlns="">
            <xhtml:th class="fr-datatable-columnset-loading-indicator"
                >&#160;...&#160;</xhtml:th>
        </header>
    </xsl:variable>

    <xsl:template match="columnSet" mode="loadingIndicator">
        <xsl:apply-templates select="$fakeColumn/header/xhtml:th"/>
    </xsl:template>



</xsl:transform>
