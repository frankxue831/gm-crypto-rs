"""Isolated research patch; leave upstream timing and statistic computation intact."""
from pathlib import Path
import sys


def patch(root):
    p = root / 'src/ctbench.rs'
    s = p.read_text()
    old = '''    let samples_iter = cb.samples.0.iter().zip(cb.samples.1.iter());
    if let Some(f) = cb.file_out.as_mut() {
        for (x, y) in samples_iter {
            write!(f, "\\n{},0,{}", name.0, x).expect("Error writing data to file");
            write!(f, "\\n{},0,{}", name.0, y).expect("Error writing data to file");
        }
    };'''
    new = '''    if let Some(f) = cb.file_out.as_mut() {
        for x in &cb.samples.0 {
            write!(f, "\\n{},0,{}", name.0, x).expect("Error writing data to file");
        }
        for y in &cb.samples.1 {
            write!(f, "\\n{},1,{}", name.0, y).expect("Error writing data to file");
        }
    };
    if let Ok(path) = std::env::var("DUDECT_CROP_OUT") {
        let mut f = OpenOptions::new().create(true).append(true).open(path).unwrap();
        stats::write_diagnostics(name.0, cb.ctx.as_ref().unwrap(), &mut f).unwrap();
    }'''
    if s.count(old) != 1:
        raise ValueError('upstream exporter changed')
    p.write_text(s.replace(old, new))
    p = root / 'src/stats.rs'
    p.write_text(p.read_text() + r'''

// Research export only: called after the existing summary has been computed.
pub(crate) fn write_diagnostics<W: std::io::Write>(name: &str, ctx: &CtCtx, out: &mut W) -> std::io::Result<()> {
    let selected = ctx.tests.iter().enumerate()
        .max_by(|(_, x), (_, y)| local_cmp(compute_t(x).abs(), compute_t(y).abs()))
        .unwrap().0;
    for (index, test) in ctx.tests.iter().enumerate() {
        let threshold = if index == 0 { f64::INFINITY } else { ctx.percentiles[index - 1] };
        let t = compute_t(test);
        let n = test.sizes.0 + test.sizes.1;
        let tau = t / (n as f64).sqrt();
        let v0 = test.sq_diffs.0 / (test.sizes.0 as f64 - 1.0);
        let v1 = test.sq_diffs.1 / (test.sizes.1 as f64 - 1.0);
        writeln!(out, "{},{},{:.17},{},{},{:.17},{:.17},{:.17},{:.17},{:.17},{:.17},{}",
            name, index, threshold, test.sizes.0, test.sizes.1,
            test.means.0, test.means.1, v0, v1, t, tau, index == selected)?;
    }
    Ok(())
}

#[cfg(test)]
mod crop_export_regression {
    use super::*;
    #[test]
    fn uncropped_welch_and_all_rows_survive_export() {
        let (summary, ctx) = update_ct_stats(None, &(vec![1, 2, 3], vec![3, 4, 5]));
        let mut out = Vec::new();
        write_diagnostics("fixture", &ctx, &mut out).unwrap();
        let text = String::from_utf8(out).unwrap();
        let rows: Vec<Vec<&str>> = text.lines().map(|s| s.split(',').collect()).collect();
        assert_eq!(rows.len(), 101);
        assert_eq!(&rows[0][3..5], &["3", "3"]);
        assert_eq!(rows[0][5].parse::<f64>().unwrap(), 2.0);
        assert_eq!(rows[0][6].parse::<f64>().unwrap(), 4.0);
        assert_eq!(rows[0][7].parse::<f64>().unwrap(), 1.0);
        assert_eq!(rows[0][8].parse::<f64>().unwrap(), 1.0);
        // Independent hand calculation: (-2)/sqrt(1/3+1/3), tau = t/sqrt(6).
        assert!((rows[0][9].parse::<f64>().unwrap() + 2.449489742783178).abs() < 1e-12);
        assert!((rows[0][10].parse::<f64>().unwrap() + 1.0).abs() < 1e-12);
        let selected: Vec<_> = rows.iter().filter(|r| r[11] == "true").collect();
        assert_eq!(selected.len(), 1);
        let selected = selected[0];
        assert_eq!(selected[3].parse::<usize>().unwrap() + selected[4].parse::<usize>().unwrap(), summary.sample_size);
        assert_eq!(selected[9].parse::<f64>().unwrap(), summary.max_t);
        assert_eq!(selected[10].parse::<f64>().unwrap(), summary.max_tau);
    }
}
''')


if __name__ == '__main__':
    patch(Path(sys.argv[1]))
