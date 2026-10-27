package com.dearlavion.authservice.superadmin;

import java.util.ArrayList;
import java.util.List;

/**
 * Cuts one page out of data that lives in several projects' databases. Given how many rows each project holds, it says
 * which slice of which project makes up the page (ordered by project, then by whatever order each project's query uses),
 * so only the projects a page actually touches are read.
 */
final class ProjectPaging {

    record Segment(String project, long skip, int take) {}

    private ProjectPaging() {}

    static List<Segment> plan(List<String> projects, long[] counts, int page, int size) {
        long skip = (long) page * size;
        int need = size;
        List<Segment> segments = new ArrayList<>();
        for (int i = 0; i < counts.length && need > 0; i++) {
            if (skip >= counts[i]) {
                skip -= counts[i];
                continue;
            }
            int take = (int) Math.min(need, counts[i] - skip);
            segments.add(new Segment(projects.get(i), skip, take));
            need -= take;
            skip = 0;
        }
        return segments;
    }
}
