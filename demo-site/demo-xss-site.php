<?php
//
// This PHP page has intentional XSS issues of various contexts that
//    triggered by named parameters for demonstration purposes.
//
// Application Security Threat Attack Modeling (ASTAM)
//
// Copyright (C) 2017 Applied Visions - http://securedecisions.com
//
// Written by Aspect Security - http://aspectsecurity.com
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
?>
<?php
  header('X-XSS-Protection: 0');
?><!doctype html>
<html>
    <head>
        <meta charset="utf-8">
        <title></title>
        <meta name="description" content="">
        <style>
          p {
            margin-left: 10%;
            margin-right: 10%;
          }

          div.hidden {
            width: 1px;
            height: 1px;
          }
        </style>
    </head>
    <body>
      <script>
        // canaries for false positives
        alert("This is not an XSS attack!");
        confirm("This is not an XSS attack!");
        console.log("This is not an XSS attack!");
        prompt("This is not an XSS attack:");
      </script>
      <h1>XSS Testing Page</h1>
      <p>The purpose of this page is to provide a testing ground for Cross-Site Scripting (XSS) tools. It is intentionally susceptible to reflected XSS in a variety of contexts. Each supported context is identified by a name in the table below. This page accepts HTTP parameters with those names and places the value in that context. For example, a request corresponding to <code>demo-xss-site.php?html=foo&amp;doubleQuotedAttribute=bar</code> would result in the value <code>foo</code> being reflected in an HTML context and the value <code>bar</code> being reflected in a double quoted HTML attribute context. See the <a href="https://www.owasp.org/index.php/XSS_(Cross_Site_Scripting)_Prevention_Cheat_Sheet">OWASP XSS Prevention Cheatsheet</a> for more information about various contexts.</p>
      <table>
        <thead>
          <tr>
            <th>Parameter Name</th>
            <th>Reflected Context</th>
            <th colspan="2">Example</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td>tagName</td>
            <td>Inside a tag declaration</td>
            <td><a href="?tagName=foo">demo-xss-site.php?tagName=foo</a></td>
            <td>&lt;foo&gt;...&lt;/foo&gt;</td>
          </tr>
          <tr>
            <td>attributeName</td>
            <td>Inside an attribute name</td>
            <td><a href="?attributeName=foo">demo-xss-site.php?attributeName=foo</a></td>
            <td>&lt;div foo=""&gt;...&lt;/div&gt;</td>
          </tr>
          <tr>
            <td>singleQuotedAttributeValue</td>
            <td>Inside an attribute value delimeted by a single quote (<code>'</code>)</td>
            <td><a href="?singleQuotedAttributeValue=foo">demo-xss-site.php?singleQuotedAttributeValue=foo</a></td>
            <td>&lt;input value='foo'&gt;...&lt;/input&gt;</td>
          </tr>
          <tr>
            <td>doubleQuotedAttributeValue</td>
            <td>Inside an attribute value delimeted by a double quote (<code>"</code>)</td>
            <td><a href="?doubleQuotedAttributeValue=foo">demo-xss-site.php?doubleQuotedAttributeValue=foo</a></td>
            <td>&lt;input value="foo"&gt;...&lt;/input&gt;</td>
          </tr>
          <tr>
            <td>unquotedAttributeValue</td>
            <td>Inside an attribute value delimeted by a double quote (<code>"</code>)</td>
            <td><a href="?unquotedAttributeValue=foo">demo-xss-site.php?unquotedAttributeValue=foo</a></td>
            <td>&lt;input value=foo&gt;...&lt;/input&gt;</td>
          </tr>
          <tr>
            <td>html</td>
            <td>In an HTML context</td>
            <td><a href="?html=foo">demo-xss-site.php?html=foo</a></td>
            <td>&lt;div&gt;... foo ...&lt;/div&gt;</td>
          </tr>
          <tr>
            <td>htmlComment</td>
            <td>Inside an HTML comment</td>
            <td><a href="?htmlComment=foo">demo-xss-site.php?htmlComment=foo</a></td>
            <td>&lt;!--... foo ... --&gt;</td>
          </tr>
          <tr>
            <td>styleTag</td>
            <td>Inside a CSS style tag</td>
            <td><a href="?styleTag=foo">demo-xss-site.php?styleTag=foo</a></td>
            <td>&lt;style&gt;... foo ...&lt;/div&gt;</td>
          </tr>
          <tr>
            <td>styleAttribute</td>
            <td>Inside a CSS style attribute</td>
            <td><a href="?styleAttribute=foo">demo-xss-site.php?styleAttribute=foo</a></td>
            <td>&lt;div style="foo"&gt;...&lt;/div&gt;</td>
          </tr>
          <tr>
            <td>idAttribute</td>
            <td>Inside an ID attribute</td>
            <td><a href="?idAttribute=foo">demo-xss-site.php?idAttribute=foo</a></td>
            <td>&lt;div id="foo"&gt;...&lt;/div&gt;</td>
          </tr>
          <tr>
            <td>classAttribute</td>
            <td>Inside a CSS class name attribute</td>
            <td><a href="?classAttribute=foo">demo-xss-site.php?classAttribute=foo</a></td>
            <td>&lt;div class="foo"&gt;...&lt;/div&gt;</td>
          </tr>

          <tr>
            <td>jsSingleQuotedString</td>
            <td>Inside a sigle quoted string in JavaScript</td>
            <td><a href="?jsSingleQuotedString=foo">demo-xss-site.php?jsSingleQuotedString=foo</a></td>
            <td>&lt;script&gt; var str = 'foo'; &lt;/script&gt;</td>
          </tr>
          <tr>
            <td>jsDoubleQuotedString</td>
            <td>Inside a double quoted string in JavaScript</td>
            <td><a href="?jsDoubleQuotedString=foo">demo-xss-site.php?jsDoubleQuotedString=foo</a></td>
            <td>&lt;script&gt; var str = "foo"; &lt;/script&gt;</td>
          </tr>
          <tr>
            <td>jsSingleLineComment</td>
            <td>Inside a single line JavaScript comment</td>
            <td><a href="?jsSingleLineComment=foo">demo-xss-site.php?jsSingleLineComment=foo</a></td>
            <td>&lt;script&gt; // foo &lt;/script&gt;</td>
          </tr>
          <tr>
            <td>jsMultiLineComment</td>
            <td>Inside a multi line JavaScript comment</td>
            <td><a href="?jsMultiLineComment=foo">demo-xss-site.php?jsMultiLineComment=foo</a></td>
            <td>&lt;script&gt; /* foo */ &lt;/script&gt;</td>
          </tr>
          <tr>
            <td>js</td>
            <td>Inside a JavaScript script tag context</td>
            <td><a href="?js=foo">demo-xss-site.php?js=foo</a></td>
            <td>&lt;script&gt; foo &lt;/script&gt;</td>
          </tr>
        </tbody>
      </table>
      <div class="hidden">
        <?php
          if (isset($_REQUEST['tagName'])) {
            echo "<" . $_REQUEST['tagName'] . ">&nbsp;</" . $_REQUEST['tagName'] . ">";
          }
        ?>

        <div <?php if (isset($_REQUEST['attributeName'])) { echo $_REQUEST['attributeName'] . "=\"\""; } ?>>&nbsp;</div>

        <div custAttr='<?php if (isset($_REQUEST['singleQuotedAttributeValue'])) { echo $_REQUEST['singleQuotedAttributeValue']; } ?>'>&nbsp;</div>
        <div custAttr="<?php if (isset($_REQUEST['doubleQuotedAttributeValue'])) { echo $_REQUEST['doubleQuotedAttributeValue']; } ?>">&nbsp;</div>
        <div custAttr=<?php if (isset($_REQUEST['unquotedAttributeValue'])) { echo $_REQUEST['unquotedAttributeValue']; } ?>>&nbsp;</div>

        <?php if (isset($_REQUEST['html'])) { echo $_REQUEST['html']; } ?>

        <!-- <?php if (isset($_REQUEST['htmlComment'])) { echo $_REQUEST['htmlComment']; } ?> -->

        <style><?php if (isset($_REQUEST['styleTag'])) { echo $_REQUEST['styleTag']; } ?></style>

        <div style="<?php if (isset($_REQUEST['styleAttribute'])) { echo $_REQUEST['styleAttribute']; } ?>">&nbsp;</div>

        <div id="<?php if (isset($_REQUEST['idAttribute'])) { echo $_REQUEST['idAttribute']; } ?>">&nbsp;</div>

        <div class="<?php if (isset($_REQUEST['classAttribute'])) { echo $_REQUEST['classAttribute']; } ?>">&nbsp;</div>
      </div>
      <script>

        var singleQuotedString = '<?php if (isset($_REQUEST['jsSingleQuotedString'])) { echo $_REQUEST['jsSingleQuotedString']; } ?>';
        var doubleQuotedString = "<?php if (isset($_REQUEST['jsDoubleQuotedString'])) { echo $_REQUEST['jsDoubleQuotedString']; } ?>";

        // <?php if (isset($_REQUEST['jsSingleLineComment'])) { echo $_REQUEST['jsSingleLineComment']; } ?>

        /* <?php if (isset($_REQUEST['jsMultiLineComment'])) { echo $_REQUEST['jsMultiLineComment']; } ?> */

        <?php if (isset($_REQUEST['js'])) { echo $_REQUEST['js']; } ?>;
      </script>
    </body>
</html>
