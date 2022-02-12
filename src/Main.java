import redos.regex.Pattern4Search;
import redos.regex.redosPattern;
import regex.Analyzer;

import java.io.*;
import java.util.Base64;
import java.util.concurrent.*;
import java.util.regex.Pattern;

import static java.lang.Thread.sleep;

/**
 * @author SuperMaxine
 */
public class Main {
    public static void main(String[] args) {
        // log begin time
        long beginTime = System.currentTimeMillis();

        // Pattern4Search testPattern = Pattern4Search.compile("(^|[^\\\\](?:\\\\\\\\)*)([\\\"'])(?:\\\\[\\s\\S]|\\$\\([^)]+\\)|`[^`]+`|(?!\\2)[^\\\\])*\\2");
        // redosPattern testPattern = redosPattern.compile("~[rR](?:(\\\"\\\"\\\"|''')(?:\\\\[\\s\\S]|(?!\\1)[^\\\\])+\\1|([\\/|\\\"'])(?:\\\\.|(?!\\2)[^\\\\\\r\\n])+\\2|\\((?:\\\\.|[^\\\\)\\r\\n])+\\)|\\[(?:\\\\.|[^\\\\\\]\\r\\n])+\\]|\\{(?:\\\\.|[^\\\\}\\r\\n])+\\}|<(?:\\\\.|[^\\\\>\\r\\n])+>)[uismxfr]*");
        // System.out.println("match step:"+testPattern.getMatchingStepCnt("", "~R\"\"", "\n\b\n", 30000, 100000000));

        // testDataSet("prism.txt");
        // testDataSet("prism-poa.txt");
        // testDataSet("prism-slq.txt");

        // testSingleRegex("((?:^|[^\\s\\w>)?])\\s*\\[\\s*)(?:(?:\\b(?:assembly|event|field|method|module|param|property|return|type)\\b)\\s*:\\s*)?(?:(?:(?!(?:\\b(?:class|enum|interface|struct|add|alias|and|ascending|async|await|by|descending|from|get|global|group|into|join|let|nameof|not|notnull|on|or|orderby|partial|remove|select|set|unmanaged|value|when|where|where|abstract|as|base|break|case|catch|checked|const|continue|default|delegate|do|else|event|explicit|extern|finally|fixed|for|foreach|goto|if|implicit|in|internal|is|lock|namespace|new|null|operator|out|override|params|private|protected|public|readonly|ref|return|sealed|sizeof|stackalloc|static|switch|this|throw|try|typeof|unchecked|unsafe|using|virtual|volatile|while|yield)\\b))(?:(?:@?\\b[A-Za-z_]\\w*\\b)(?:\\s*(?:<(?:[^<>;=+\\-*\\/%&|^]|(?:<(?:[^<>;=+\\-*\\/%&|^]|(?:<(?:[^<>;=+\\-*\\/%&|^]|(?:<(?:[^<>;=+\\-*\\/%&|^]|[^\\s\\S])*>))*>))*>))*>))?)(?:\\s*\\.\\s*(?:(?:@?\\b[A-Za-z_]\\w*\\b)(?:\\s*(?:<(?:[^<>;=+\\-*\\/%&|^]|(?:<(?:[^<>;=+\\-*\\/%&|^]|(?:<(?:[^<>;=+\\-*\\/%&|^]|(?:<(?:[^<>;=+\\-*\\/%&|^]|[^\\s\\S])*>))*>))*>))*>))?))*)(?:\\s*\\((?:[^\\\"'\\/()]|(?:\\/(?![*\\/])|\\/\\/[^\\r\\n]*[\\r\\n]|\\/\\*(?:[^*]|\\*(?!\\/))*\\*\\/|(?:\\\"(?:\\\\.|[^\\\\\\\"\\r\\n])*\\\"|'(?:[^\\r\\n'\\\\]|\\\\.|\\\\[Uux][\\da-fA-F]{1,8})'))|\\((?:[^\\\"'\\/()]|(?:\\/(?![*\\/])|\\/\\/[^\\r\\n]*[\\r\\n]|\\/\\*(?:[^*]|\\*(?!\\/))*\\*\\/|(?:\\\"(?:\\\\.|[^\\\\\\\"\\r\\n])*\\\"|'(?:[^\\r\\n'\\\\]|\\\\.|\\\\[Uux][\\da-fA-F]{1,8})'))|\\((?:[^\\\"'\\/()]|(?:\\/(?![*\\/])|\\/\\/[^\\r\\n]*[\\r\\n]|\\/\\*(?:[^*]|\\*(?!\\/))*\\*\\/|(?:\\\"(?:\\\\.|[^\\\\\\\"\\r\\n])*\\\"|'(?:[^\\r\\n'\\\\]|\\\\.|\\\\[Uux][\\da-fA-F]{1,8})'))|\\((?:[^\\\"'\\/()]|(?:\\/(?![*\\/])|\\/\\/[^\\r\\n]*[\\r\\n]|\\/\\*(?:[^*]|\\*(?!\\/))*\\*\\/|(?:\\\"(?:\\\\.|[^\\\\\\\"\\r\\n])*\\\"|'(?:[^\\r\\n'\\\\]|\\\\.|\\\\[Uux][\\da-fA-F]{1,8})'))|\\([^\\s\\S]*\\))*\\))*\\))*\\))*\\))?)(?=\\s*\\])");
        // testSingleRegex("((?:^|\\r?\\n|\\r)[\\t ]*)[%.#][\\w\\-#.]*[\\w\\-](?:\\([^)]+\\)|\\{(?:\\{[^}]+\\}|[^}])+\\}|\\[[^\\]]+\\])*[\\/<>]*");
        // testSingleRegex("(^|[^@\\\\])\\$\\\"(?:\\\\.|\\{\\{|(?:\\{(?!\\{)(?:(?![}:])(?:[^\\\"'/()]|\\/(?!\\*)|\\/\\*(?:[^*]|\\*(?!\\/))*\\*\\/|(?:\\\"(?:\\\\.|[^\\\\\\\"\\r\\n])*\\\"|'(?:[^\\r\\n'\\\\]|\\\\.|\\\\[Uux][\\da-fA-F]{1,8})')|\\((?:[^\\\"'/()]|\\/(?!\\*)|\\/\\*(?:[^*]|\\*(?!\\/))*\\*\\/|(?:\\\"(?:\\\\.|[^\\\\\\\"\\r\\n])*\\\"|'(?:[^\\r\\n'\\\\]|\\\\.|\\\\[Uux][\\da-fA-F]{1,8})')|\\((?:[^\\\"'/()]|\\/(?!\\*)|\\/\\*(?:[^*]|\\*(?!\\/))*\\*\\/|(?:\\\"(?:\\\\.|[^\\\\\\\"\\r\\n])*\\\"|'(?:[^\\r\\n'\\\\]|\\\\.|\\\\[Uux][\\da-fA-F]{1,8})')|\\((?:[^\\\"'/()]|\\/(?!\\*)|\\/\\*(?:[^*]|\\*(?!\\/))*\\*\\/|(?:\\\"(?:\\\\.|[^\\\\\\\"\\r\\n])*\\\"|'(?:[^\\r\\n'\\\\]|\\\\.|\\\\[Uux][\\da-fA-F]{1,8})')|\\([^\\s\\S]*\\))*\\))*\\))*\\)))*(?::[^}\\r\\n]+)?\\})|[^\\\\\\\"{])*\\\"");
        try {
            testSingleRegex("((?:^|[&(])[ \\t]*)for(?: ?\\/[a-z?](?:[ :](?:\\\"[^\\\"]*\\\"|[^\\s\\\"/]\\S*))?)* \\S+ in \\([^)]+\\) do");
        } catch (StackOverflowError e) {
            e.printStackTrace();
        }

        // log end time and print run time
        long endTime = System.currentTimeMillis();
        System.out.println("Total run time: " + (endTime - beginTime) + "ms");
    }

    private static void testSingleRegex(String regex) {
        // log start time
        long startTime = System.currentTimeMillis();
        Analyzer a = new Analyzer(regex, 10, -1);
        // log end time and print run time
        long endTime = System.currentTimeMillis();
        System.out.println(a.attackable);
        System.out.println(a.attackMsg);
        System.out.println("Run time: " + (endTime - startTime) + "ms");
    }

    private static void testDataSet(String file) {
        InputStream inputStream = Main.class.getClassLoader().getResourceAsStream(file);
        BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(inputStream));
        // 如果不存在result.txt文件，则创建
        if (!new File("result-"+file).exists()) {
            try {
                new File("result-"+file).createNewFile();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        ExecutorService es;
        // int count = 981;
        int count = 1;
        String str = null;
        while (true) {
            try {
                if (!((str = bufferedReader.readLine()) != null)) break;
                if (count <= 0) {
                    count++;
                    continue;
                }
                Tester t = new Tester();
                t.regexAnalyzeLimitTime(str, count, file);
            } catch (IOException e) {
                e.printStackTrace();
            }
            count++;
            // sleep 2 second
            try {
                sleep(100);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }

        //close
        try {
            inputStream.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}

class Tester {
    boolean runTime = false;
    // boolean runTime = true;

    // boolean realTest = false;
    boolean realTest = true;

    long startTime = 0;
    long endTime = 0;

    class attackResult {
        public boolean attackable;
        public String attackMsg;

        public attackResult() {
            attackable = false;
            attackMsg = "";
        }

        public attackResult(boolean attackable, String attackMsg) {
            this.attackable = attackable;
            this.attackMsg = attackMsg;
        }
    }

    public void regexAnalyzeLimitTime(String regex, int id, String file) {
        attackResult attackMsg;
        final ExecutorService exec = Executors.newFixedThreadPool(1);
        Callable<attackResult> call = new Callable<attackResult>() {
            @Override
            public attackResult call() throws Exception {
                //开始执行耗时操作 ，这个方法为你要限制执行时间的方法
                try {
                    Analyzer a = new Analyzer(regex, 10, id);
                    return new attackResult(a.attackable, a.attackMsg);
                } catch (Exception e) {
                    e.printStackTrace();
                    String base64Exception = "";
                    try {
                        base64Exception = Base64.getEncoder().encodeToString(e.toString().getBytes("utf-8"));
                    } catch (UnsupportedEncodingException ee) {
                        e.printStackTrace();
                    }
                    return new attackResult(false, base64Exception);
                }
            }
        };
        String result = "";
        Future<attackResult> future = null;
        String base64Regex = "";

        if (runTime) {
            // log start time
            startTime = System.currentTimeMillis();
        }

        try {
            base64Regex = Base64.getEncoder().encodeToString(regex.getBytes("utf-8"));
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        try {
            future = exec.submit(call);
            //返回值类型为限制的方法的返回值类型
            attackMsg = future.get(1000 * 5, TimeUnit.MILLISECONDS); //任务处理超时时间设为 5 秒

            if (realTest) result += id + "," + base64Regex + "," + attackMsg.attackable + "," + attackMsg.attackMsg + "\n";
            if (runTime) result += "success,";
        } catch (TimeoutException ex) {
            future.cancel(true);
            if (realTest) result += id + "," + base64Regex + "," + "Timeout\n";
            if (runTime) result += "timeout,";
        } catch (Exception e) {
            String base64Exception = "";
            try {
                base64Exception = Base64.getEncoder().encodeToString(e.toString().getBytes("utf-8"));
            } catch (UnsupportedEncodingException ee) {
                e.printStackTrace();
            }
            if (realTest) result += id + "," + base64Regex + "," + base64Exception + "\n";
            if (runTime) result += "exception,";
            e.printStackTrace();
        }

        if (runTime) {
            // log end time
            endTime = System.currentTimeMillis();
            result += (endTime - startTime) + "," + base64Regex + "\n";
        }

        // System.out.println(result);
        BufferedWriter writer = null;
        try {
            writer = new BufferedWriter(new FileWriter("result-"+file, true));
            writer.write(result);
            writer.close();
        } catch (IOException e) {
            e.printStackTrace();
        }

        // 关闭线程池
        exec.shutdown();
        return;
    }
}
