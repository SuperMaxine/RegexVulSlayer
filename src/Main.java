import regex.Analyzer;

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
        // // testSingleRegex("(^[ \\t]*)(?:(?=\\S)(?:[^{}\\r\\n:()]|::?[\\w-]+(?:\\([^)\\r\\n]*\\))?|\\{[^}\\r\\n]+\\})+)(?:(?:\\r?\\n|\\r)(?:\\1(?:(?=\\S)(?:[^{}\\r\\n:()]|::?[\\w-]+(?:\\([^)\\r\\n]*\\))?|\\{[^}\\r\\n]+\\})+)))*(?:,$|\\{|(?=(?:\\r?\\n|\\r)(?:\\{|\\1[ \\t]+)))");
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
        testSingleRegex("#?[_$a-zA-Z\\xA0-\\uFFFF][$\\w\\xA0-\\uFFFF]*(?=\\s*(?:\\.\\s*(?:apply|bind|call)\\s*)?\\()");


        // testSingleRegex("");
        // testSingleRegex("");
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
