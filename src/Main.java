import regex.Analyzer;

import java.io.UnsupportedEncodingException;
import java.util.Base64;

/**
 * @author SuperMaxine
 */
public class Main {
    public static void main(String[] args) {
        // prism中所有标出的NQ、EOA、EOD都可测出
        // testSingleRegex("^(a|(?=abc)\\w+)+$");
        // testSingleRegex("(\\()lambda\\s+\\((?:&?[-+*/_~!@$%^=<>{}\\w]+\\s*)*\\)");
        // testSingleRegex("((?:^|[&(])[ \\t]*)for(?: ?\\/[a-z?](?:[ :](?:\\\"[^\\\"]*\\\"|[^\\s\\\"/]\\S*))?)* \\S+ in \\([^)]+\\) do");
        // testSingleRegex("((?:^|[&(])[ \\t]*)if(?: ?\\/[a-z?](?:[ :](?:\\\"[^\\\"]*\\\"|[^\\s\\\"/]\\S*))?)* (?:not )?(?:cmdextversion \\d+|defined \\w+|errorlevel \\d+|exist \\S+|(?:\\\"[^\\\"]*\\\"|[^\\s\\\"]\\S*)?(?:==| (?:equ|neq|lss|leq|gtr|geq) )(?:\\\"[^\\\"]*\\\"|[^\\s\\\"]\\S*))");
        // testSingleRegex("((?:^|[&(])[ \\t]*)set(?: ?\\/[a-z](?:[ :](?:\\\"[^\\\"]*\\\"|[^\\s\\\"/]\\S*))?)* (?:[^^&)\\r\\n]|\\^(?:\\r\\n|[\\s\\S]))*");
        // testSingleRegex("^\\|={3,}(?:(?:\\r?\\n|\\r).*)*?(?:\\r?\\n|\\r)\\|={3,}$");
        // testSingleRegex("(^|[^\\\\])(?:(?:\\B\\[(?:[^\\]\\\\\\\"]|([\\\"'])(?:(?!\\2)[^\\\\]|\\\\.)*\\2|\\\\.)*\\])?(?:\\b_(?!\\s)(?: _|[^_\\\\\\r\\n]|\\\\.)+(?:(?:\\r?\\n|\\r)(?: _|[^_\\\\\\r\\n]|\\\\.)+)*_\\b|\\B``(?!\\s).+?(?:(?:\\r?\\n|\\r).+?)*''\\B|\\B`(?!\\s)(?:[^`'\\s]|\\s+\\S)+['`]\\B|\\B(['*+#])(?!\\s)(?: \\3|(?!\\3)[^\\\\\\r\\n]|\\\\.)+(?:(?:\\r?\\n|\\r)(?: \\3|(?!\\3)[^\\\\\\r\\n]|\\\\.)+)*\\3\\B)|(?:\\[(?:[^\\]\\\\\\\"]|([\\\"'])(?:(?!\\4)[^\\\\]|\\\\.)*\\4|\\\\.)*\\])?(?:(__|\\*\\*|\\+\\+\\+?|##|\\$\\$|[~^]).+?(?:(?:\\r?\\n|\\r).+?)*\\5|\\{[^}\\r\\n]+\\}|\\[\\[\\[?.+?(?:(?:\\r?\\n|\\r).+?)*\\]?\\]\\]|<<.+?(?:(?:\\r?\\n|\\r).+?)*>>|\\(\\(\\(?.+?(?:(?:\\r?\\n|\\r).+?)*\\)?\\)\\)))");
        // testSingleRegex("(?:\\[(?:[^\\]\\\\\\\"]|([\\\"'])(?:(?!\\1)[^\\\\]|\\\\.)*\\1|\\\\.)*\\])");
        // testSingleRegex("(^|[^\\\\](?:\\\\\\\\)*)([\\\"'])(?:\\\\[\\s\\S]|\\$\\([^)]+\\)|`[^`]+`|(?!\\2)[^\\\\])*\\2");
        // testSingleRegex("((?:^|[&(])[ \\t]*)for(?: ?\\/[a-z?](?:[ :](?:\\\"[^\\\"]*\\\"|[^\\s\\\"/]\\S*))?)* \\S+ in \\([^)]+\\) do");
        // testSingleRegex("((?:^|[&(])[ \\t]*)if(?: ?\\/[a-z?](?:[ :](?:\\\"[^\\\"]*\\\"|[^\\s\\\"/]\\S*))?)* (?:not )?(?:cmdextversion \\d+|defined \\w+|errorlevel \\d+|exist \\S+|(?:\\\"[^\\\"]*\\\"|[^\\s\\\"]\\S*)?(?:==| (?:equ|neq|lss|leq|gtr|geq) )(?:\\\"[^\\\"]*\\\"|[^\\s\\\"]\\S*))");
        // testSingleRegex("((?:^|[&(])[ \\t]*)set(?: ?\\/[a-z](?:[ :](?:\\\"[^\\\"]*\\\"|[^\\s\\\"/]\\S*))?)* (?:[^^&)\\r\\n]|\\^(?:\\r\\n|[\\s\\S]))*");
        // testSingleRegex("(\\\"|')(?:#\\{[^}]+\\}|\\\\(?:\\r\\n|[\\s\\S])|(?!\\1)[^\\\\\\r\\n])*\\1");
        // testSingleRegex("\\\"(?:[^\\\\\\\"\\r\\n]|\\\\(?:[abfnrtv\\\\\\\"]|\\d+|x[0-9a-fA-F]+))*\\\"");
        // testSingleRegex("([\\\"'])(?:(?!\\1)[^\\\\\\r\\n]|\\\\z(?:\\r\\n|\\s)|\\\\(?:\\r\\n|[\\s\\S]))*\\1|\\[(=*)\\[[\\s\\S]*?\\]\\2\\]");
        // testSingleRegex("(^[ \\t]*)(?:(?=\\S)(?:[^{}\\r\\n:()]|::?[\\w-]+(?:\\([^)\\r\\n]*\\))?|\\{[^}\\r\\n]+\\})+)(?:(?:\\r?\\n|\\r)(?:\\1(?:(?=\\S)(?:[^{}\\r\\n:()]|::?[\\w-]+(?:\\([^)\\r\\n]*\\))?|\\{[^}\\r\\n]+\\})+)))*(?:,$|\\{|(?=(?:\\r?\\n|\\r)(?:\\{|\\1[ \\t]+)))");
        // testSingleRegex("(^|\\r?\\n|\\r)\\/[\\t ]*(?:(?:\\r?\\n|\\r)(?:.*(?:\\r?\\n|\\r))*?(?:\\\\(?=[\\t ]*(?:\\r?\\n|\\r))|$)|\\S.*)"); // 需要将后缀改为!
        // testSingleRegex("=(?:(\"|')(?:\\\\[\\s\\S]|\\{(?!\\{)(?:\\{(?:\\{[^{}]*}|[^{}])*}|[^{}])+}|(?!\\1)[^\\\\])*\\1|[^\\s'\">=]+)");


        // prism中前60个SLQ，除了StackOverflowError问题都可测出
        // testSingleRegex("(^|)a+b+");
        // testSingleRegex("<!--[\\s\\S]*?-->");
        // testSingleRegex("<\\?[\\s\\S]+?\\?>");
        // testSingleRegex("<\\?[\\s\\S]+?\\?>");
        // testSingleRegex("<!DOCTYPE(?:\\[^>\\\"'[\\]]|\\\"[^\\\"]*\\\"|'[^']*')+(?:\\[(?:[^<\\\"'\\]]|\\\"[^\\\"]*\\\"|'[^']*'|<(?!!--)|<!--(?:[^-]|-(?!->))*-->)*\\]\\s*)?>"); //攻击串长度限制要调到13
        // testSingleRegex("<\\/?(?!\\d)[^\\s>\\/=$<%]+(?:\\s(?:\\s*[^\\s>\\/=]+(?:\\s*=\\s*(?:\\\"[^\\\"]*\\\"|'[^']*'|[^\\s'\\\">=]+(?=[\\s>]))|(?=[\\s/>])))+)?\\s*\\/?>");
        // testSingleRegex("(\\[)[\\s\\S]+(?=\\]>$)");
        // testSingleRegex("\\=\\S*(?:\\\"[^\\\"]*\\\"|'[^']*'|[^\\s'\\\">=]+)");
        // testSingleRegex("\\/\\*[\\s\\S]*?\\*\\/");
        /*
        下面这个可以生成攻击串“”+“\"”*n+“\n\b\n”，但是引擎报错StackOverflowError，尝试直接测试，长度一长也会报StackOverflowError，在报错之前趋势是这样的
        32ms    n = 500
        99ms    n = 1000
        215ms   n = 1500
        378ms   n = 2000
        报错StackOverflowError    n = 2500
        师兄给的"" + "a".repeat(i*10000) + "\n!\n";同理，也是StackOverflowError
        */
        // testSingleRegex("[^{}\\s](?:[^{};\\\"']|(\\\"|')(?:\\\\(?:\\r\\n|[\\s\\S])|(?!\\1)[^\\\\\\r\\n])*\\1)*?(?=\\s*\\{)");
        // testSingleRegex("[-_a-z\\xA0-\\uFFFF][-\\w\\xA0-\\uFFFF]*(?=\\s*:)"); // 下面这个没有添加常用字符集就检测不出来，加了就好了
        // testSingleRegex("[-a-z0-9]+(?=\\()");
        // 同上StackOverflowError，攻击串“”+“\"”*n+“\n\b\n”，似乎有反向引用就容易引发StackOverflowError
        // testSingleRegex("(\\\"|')(?:\\\\(?:\\r\\n|[\\s\\S])|(?!\\1)[^\\\\\\r\\n])*\\1");
        // testSingleRegex("(<style[\\s\\S]*?>)(?:<!\\[CDATA\\[(?:[^\\]]|\\](?!\\]>))*\\]\\]>|(?!<!\\[CDATA\\[)[\\s\\S])*?(?=<\\/style>)");
        // testSingleRegex("\\s*style=(\\\"|')(?:\\\\[\\s\\S]|(?!\\1)[^\\\\])*\\1");
        // testSingleRegex("\\w+(?=\\()");
        // 同上StackOverflowError，攻击串“”+“\"”*n+“\n\b\n”，似乎有反向引用就容易引发StackOverflowError
        // testSingleRegex("([\\\"'])(?:\\\\(?:\\r\\n|[\\s\\S])|(?!\\1)[^\\\\\\r\\n])*\\1");
        // testSingleRegex("#?[_$a-zA-Z\\xA0-\\uFFFF][$\\w\\xA0-\\uFFFF]*(?=\\s*(?:\\.\\s*(?:apply|bind|call)\\s*)?\\()");

        // POA
        testSingleRegex("(?:[+*?]|\\{(?:\\d+,?\\d*)\\})[?+]?");
        // testSingleRegex("(^[ \\t]*)[^:\\r\\n]+?(?=:)");
        // testSingleRegex("\\b(?:0x[\\da-f]+|(?:\\d+\\.?\\d*|\\.\\d+)(?:e[+-]?\\d+)?)(?:F|U(?:LL?)?|LL?)?\\b");
        // testSingleRegex("(->\\s*)(?:\\s*(?:,\\s*)?\\b[a-z]\\w*(?:\\s*\\([^()\\r\\n]*\\))?)+(?=\\s*;)");
        // testSingleRegex("(?:\\b\\d+\\.?\\d*|\\B\\.\\d+)(?:e-?\\d+)?\\b");
        // testSingleRegex("(\\b(?:class|struct)\\s+\\w+\\s*:\\s*)(?:[^;{}\\\"'])+?(?=\\s*[;{])"); // 这个虽然也是slq poa但是结果有攻击效果
        // testSingleRegex("^\\d+.*$");
        // testSingleRegex("(<script(?=.*runat=['\\\"]?server['\\\"]?)[\\s\\S]*?>)[\\s\\S]*?(?=<\\/script>)");
        // testSingleRegex("(^\\s*)#(?:comments-start|cs)[\\s\\S]*?^\\s*#(?:comments-end|ce)");
        // testSingleRegex("\\b0b[01][01_]*L?\\b|\\b0x[\\da-f_]*\\.?[\\da-f_p+-]+\\b|(?:\\b\\d[\\d_]*\\.?[\\d_]*|\\B\\.\\d[\\d_]*)(?:e[+-]?\\d[\\d_]*)?[dfls]?");
        // testSingleRegex("\\b0x[a-f\\d]+\\.?[a-f\\d]*(?:p[+-]?\\d+)?\\b|\\b\\d+(?:\\.\\B|\\.?\\d*(?:e[+-]?\\d+)?\\b)|\\B\\.\\d+(?:e[+-]?\\d+)?\\b");
        // testSingleRegex("@[\\w-]+[\\s\\S]*?(?:;|(?=\\s*\\{))");
        // testSingleRegex("(\\bselector\\s*\\((?!\\s*\\))\\s*)(?:[^()]|\\((?:[^()]|\\([^()]*\\))*\\))+?(?=\\s*\\))");
        // testSingleRegex("\\b[a-z\\d][a-z\\d-]*::?(?:(?:\\S+)??\\[(?:[^\\]\\\\\\\"]|([\\\"'])(?:(?!\\1)[^\\\\]|\\\\.)*\\1|\\\\.)*\\])");


        // 有问题的POA
        // StackOverflowError
        // testSingleRegex("[^{}\\s](?:[^{};\\\"']|(\\\"|')(?:\\\\(?:\\r\\n|[\\s\\S])|(?!\\1)[^\\\\\\r\\n])*\\1)*?(?=\\s*\\{)");
        // testSingleRegex("(<style[\\s\\S]*?>)(?:<!\\[CDATA\\[(?:[^\\]]|\\](?!\\]>))*\\]\\]>|(?!<!\\[CDATA\\[)[\\s\\S])*?(?=<\\/style>)");
        // testSingleRegex("(<script[\\s\\S]*?>)(?:<!\\[CDATA\\[(?:[^\\]]|\\](?!\\]>))*\\]\\]>|(?!<!\\[CDATA\\[)[\\s\\S])*?(?=<\\/script>)");
        /*
        时间太长从counting太多了，师兄给的"default(" + " ".repeat(i*10000) + ".\n!\n";自己测试又遇StackOverflowError，无法确定具体攻击位置
         */
        // testSingleRegex("(\\b(?:default|typeof|sizeof)\\s*\\(\\s*)(?:[^()\\s]|\\s(?!\\s*\\))|(?:\\((?:[^()]|(?:\\((?:[^()]|(?:\\((?:[^()]|(?:\\((?:[^()]|[^\\s\\S])*\\)))*\\)))*\\)))*\\)))*(?=\\s*\\))");
        /**
         * 这些都不是纯POA，运行时间长或测出来的攻击串没有攻击效应
         */
        // testSingleRegex("#?[_$a-zA-Z\\xA0-\\uFFFF][$\\w\\xA0-\\uFFFF]*(?=\\s*(?:\\.\\s*(?:apply|bind|call)\\s*)?\\()");
        // testSingleRegex("#?[_$a-zA-Z\\xA0-\\uFFFF][$\\w\\xA0-\\uFFFF]*(?=\\s*[=:]\\s*(?:async\\s*)?(?:\\bfunction\\b|(?:\\((?:[^()]|\\([^()]*\\))*\\)|[_$a-zA-Z\\xA0-\\uFFFF][$\\w\\xA0-\\uFFFF]*)\\s*=>))");
        // testSingleRegex("(\\(\\s*)(?!\\s)(?:[^()]|\\([^()]*\\))+?(?=\\s*\\)\\s*=>)");
        // testSingleRegex("((?:\\b|\\s|^)(?!(?:as|async|await|break|case|catch|class|const|continue|debugger|default|delete|do|else|enum|export|extends|finally|for|from|function|get|if|implements|import|in|instanceof|interface|let|new|null|of|package|private|protected|public|return|set|static|super|switch|this|throw|try|typeof|undefined|var|void|while|with|yield)(?![$\\w\\xA0-\\uFFFF]))(?:[_$A-Za-z\\xA0-\\uFFFF][$\\w\\xA0-\\uFFFF]*\\s*)\\(\\s*|\\]\\s*\\(\\s*)(?!\\s)(?:[^()]|\\([^()]*\\))+?(?=\\s*\\)\\s*\\{)");
        /*
        下面这个不知道算不算有攻击效果：
        prefix:<
        pump:If
        suffix:\n\b\n
        173ms   n = 10000
        535ms   n = 20000
        989ms   n = 30000
        1516ms  n = 40000
         */
        // testSingleRegex("<\\/?\\b(?:Auth[nz]ProviderAlias|Directory|DirectoryMatch|Else|ElseIf|Files|FilesMatch|If|IfDefine|IfModule|IfVersion|Limit|LimitExcept|Location|LocationMatch|Macro|Proxy|Require(?:All|Any|None)|VirtualHost)\\b *.*>");
        /*
        师兄给的攻击串"" + "\u2028".repeat(i*10000) + "|=\n!\n";不可能被POA策略挑出，总共只有两个counting，且是相邻。\s*和[-*\w\xA0-\uFFFF]*不可能重合出"\u2028"
         */
        // testSingleRegex("^(\\s*)[-*\\w\\xA0-\\uFFFF]*\\|(?!=)"); // false
        // testSingleRegex("(=\\s*)[-\\w\\xA0-\\uFFFF]+(?=\\s*$)"); // false，同上，作为中间加了内容的两个counting，\s*[-\w\xA0-\uFFFF]+与\s*、\s*与[-\w\xA0-\uFFFF]+\s*两种都不可能重合出"\u2028"
    }

    private static void testSingleRegex(String regex) {
        // log start time
        long startTime = System.currentTimeMillis();
        Analyzer a = new Analyzer(regex, 10);
        // log end time and print run time
        long endTime = System.currentTimeMillis();
        System.out.println(a.attackable);
        System.out.println(a.attackMsg);
        System.out.println("Run time: " + (endTime - startTime) + "ms");
    }
}
