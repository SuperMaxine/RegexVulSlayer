package regex;

import java.util.ArrayList;
import java.util.Set;

public class Path {
    ArrayList<PathNode> path;
    ArrayList<ArrayList<Set<Integer>>> realPaths;
    int realCharCount;
    boolean generatedRealPath;

    Path() {
        path = new ArrayList<>();
        realCharCount = 0;
        generatedRealPath = false;
    }

    Path(Path p) {
        path = new ArrayList<PathNode>(p.getPath());
        realCharCount = p.realCharCount;
    }

    public ArrayList<PathNode> getPath() {
        return path;
    }

    public ArrayList<ArrayList<Set<Integer>>> getRealPaths() {
        // TODO: 并未实现实际功能
        if (!generatedRealPath) {
            realPaths = new ArrayList<>();

            ArrayList<Set<Integer>> tmpRealPath = new ArrayList<>();
            for (PathNode node : path) {
                tmpRealPath.add(node.getCharSet());
            }
            generatedRealPath = true;

            realPaths.add(tmpRealPath);
        }
        return realPaths;
    }

    public void add(PathNode node) {
        path.add(node);
        if (node.isSet()) {
            realCharCount++;
        }
    }

    public void addAll(Path p) {
        path.addAll(p.getPath());
        realCharCount += p.realCharCount;
    }
}
