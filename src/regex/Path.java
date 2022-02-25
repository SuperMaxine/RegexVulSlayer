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

    public ArrayList<ArrayList<Set<Integer>>> getRealPaths(boolean isPump) {
        // TODO: 并未实现实际功能
        if (!generatedRealPath) {
            realPaths = new ArrayList<>();

            // ArrayList<Set<Integer>> tmpRealPath = new ArrayList<>();
            // for (PathNode node : path) {
            //     if (node.isSet()) {
            //         tmpRealPath.add(node.getCharSet());
            //     }
            // }
            // generatedRealPath = true;
            //
            // realPaths.add(tmpRealPath);

            ArrayList<Set<Integer>> tmpRealPath = new ArrayList<>();
            ArrayList<PathNode> SatisfyPath = returnSatisfyPath(path, path.size() - 1, isPump);
            if (SatisfyPath == null) return realPaths;
            for (PathNode tmpPath : SatisfyPath) {
                if (tmpPath.isSet()) {
                    tmpRealPath.add(tmpPath.getCharSet());
                }
            }

            realPaths.add(tmpRealPath);

        }
        return realPaths;
    }

    private synchronized ArrayList<PathNode> returnSatisfyPath(ArrayList<PathNode> path, int index, boolean isPump) {
        if (index < 0) return path;
        ArrayList<PathNode> newPath = null;
        if (path.get(index).isSet()) {
            newPath = returnSatisfyPath(path, index - 1, isPump);
        }
        else if (path.get(index).isLookaround()) {
            if (this.realCharCount == 0) return null;
            for (Path lookaroundPath : path.get(index).getLookaroundPath()) {
                for (ArrayList<Set<Integer>> realLookaroundPath : lookaroundPath.getRealPaths(false)) {
                    ArrayList<PathNode> tmpPath = copyPath(path);
                    int i = index;
                    for (Set<Integer> realCharSet : realLookaroundPath) {
                        if (tmpPath.get(index).getLookaroundType() == Analyzer.lookaroundType.Pos || tmpPath.get(index).getLookaroundType() == Analyzer.lookaroundType.Neg) {
                            while (!tmpPath.get(i).isSet() && this.realCharCount > 0) {
                                i++;
                                if (i >= tmpPath.size()) {
                                    if (isPump) i = 0;
                                    else {
                                        tmpPath = null;
                                        break;
                                    }
                                }
                            }
                        }
                        else {
                            while (!tmpPath.get(i).isSet()) {
                                i--;
                                if (i < 0) {
                                    if (isPump) i = tmpPath.size() - 1;
                                    else {
                                        tmpPath = null;
                                        break;
                                    }
                                }
                            }
                        }

                        if (tmpPath != null) {
                            Set<Integer> tmpSet = tmpPath.get(i).getCharSet();
                            if (tmpPath.get(index).getLookaroundType() == Analyzer.lookaroundType.Pos || tmpPath.get(index).getLookaroundType() == Analyzer.lookaroundType.Behind) {
                                tmpSet.retainAll(realCharSet);
                            }
                            else {
                                tmpSet.removeAll(realCharSet);
                            }
                            if (tmpSet.size() == 0) {
                                tmpPath = null;
                                break;
                            }
                            else {
                                tmpPath.get(i).setCharSet(tmpSet);
                            }
                        }
                    }
                    if (tmpPath != null) {
                        newPath = returnSatisfyPath(tmpPath, index - 1, isPump);
                        if (newPath == null) continue;
                        break;
                    }
                    else {
                        continue;
                    }
                }
                if (newPath != null) break;
            }
        }
        else if (path.get(index).isBound()) {
            // newPath = returnSatisfyPath(path, index - 1, isPump);
            int i = index, j = index;
            boolean atBegin = false;
            boolean atEnd = false;
            while (!path.get(i).isSet() && this.realCharCount > 0) {
                i++;
                if (i >= path.size()) {
                    if (isPump) i = 0;
                    else {
                        atBegin = true;
                        break;
                    }
                }
            }
            while (!path.get(j).isSet()) {
                j--;
                if (j < 0) {
                    if (isPump) j = path.size() - 1;
                    else {
                        atEnd = true;
                        break;
                    }
                }
            }

            if (atBegin && atEnd) {
                return null;
            }

            if (!isPump && (atBegin || atEnd)) {
                ArrayList<PathNode> tmpPath = copyPath(path);
                if (tmpPath.get(index).getbType() == PathNode.boundType.lower) {
                    if (atBegin) {
                        tmpPath.get(j).getCharSet().retainAll(Analyzer.word);
                        if (tmpPath.get(j).getCharSet().size() == 0) {
                            return null;
                        }
                    }
                    else {
                        tmpPath.get(i).getCharSet().retainAll(Analyzer.word);
                        if (tmpPath.get(i).getCharSet().size() == 0) {
                            return null;
                        }
                    }
                }
                else if (tmpPath.get(index).getbType() == PathNode.boundType.upper) {
                    if (atBegin) {
                        tmpPath.get(j).getCharSet().retainAll(Analyzer.noneWord);
                        if (tmpPath.get(j).getCharSet().size() == 0) {
                            return null;
                        }
                    }
                    else {
                        tmpPath.get(i).getCharSet().retainAll(Analyzer.noneWord);
                        if (tmpPath.get(i).getCharSet().size() == 0) {
                            return null;
                        }
                    }
                }
                newPath = returnSatisfyPath(tmpPath, index - 1, isPump);
            }
            else {
                ArrayList<ArrayList<Set<Integer>>> BoundPaths = new ArrayList<>();
                ArrayList<Set<Integer>> BoundPath = new ArrayList<>();
                if (path.get(index).getbType() == PathNode.boundType.lower) {
                    BoundPath.add(Analyzer.word);
                    BoundPath.add(Analyzer.noneWord);
                    BoundPaths.add(BoundPath);
                    BoundPath = new ArrayList<>();
                    BoundPath.add(Analyzer.noneWord);
                    BoundPath.add(Analyzer.word);
                    BoundPaths.add(BoundPath);
                }
                else if (path.get(index).getbType() == PathNode.boundType.upper) {
                    BoundPath.add(Analyzer.noneWord);
                    BoundPath.add(Analyzer.noneWord);
                    BoundPaths.add(BoundPath);
                    BoundPath = new ArrayList<>();
                    BoundPath.add(Analyzer.word);
                    BoundPath.add(Analyzer.word);
                    BoundPaths.add(BoundPath);
                }

                for (ArrayList<Set<Integer>> boundPath : BoundPaths) {
                    ArrayList<PathNode> tmpPath = copyPath(path);
                    tmpPath.get(i).getCharSet().retainAll(boundPath.get(0));
                    tmpPath.get(j).getCharSet().retainAll(boundPath.get(1));
                    if (tmpPath.get(i).getCharSet().size() == 0 || tmpPath.get(j).getCharSet().size() == 0) {
                        continue;
                    }
                    else {
                        newPath = returnSatisfyPath(tmpPath, index - 1, isPump);
                        if (newPath != null) {
                            return newPath;
                        }
                    }
                }
            }

        }
        return newPath;
    }

    public ArrayList<PathNode> copyPath(ArrayList<PathNode> path) {
        ArrayList<PathNode> newPath = new ArrayList<>();
        for (PathNode node : path) {
            newPath.add(new PathNode(node));
        }
        return newPath;
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

    public int getSize() {
        return path.size();
    }

    public int getRealCharSize() {
        return realCharCount;
    }
}
