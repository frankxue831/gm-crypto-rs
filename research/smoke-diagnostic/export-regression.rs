

#[cfg(test)]
mod export_regression {
    use super::*;
    #[test]
    fn raw_export_keeps_both_labels_and_unequal_class_lengths() {
        fn fixture(runner: &mut CtRunner, _: &mut BenchRng) {
            runner.runtimes = (vec![10, 20, 30], vec![40, 50]);
        }
        let path = std::env::temp_dir().join(format!("dudect-export-{}.csv", std::process::id()));
        let mut cb = CtBencher::new();
        cb.file_out = Some(File::create(&path).unwrap());
        run_bench_with_bencher(&BenchName("fixture"), fixture, &mut cb);
        drop(cb);
        let actual = std::fs::read_to_string(&path).unwrap();
        std::fs::remove_file(path).unwrap();
        assert_eq!(actual, "\nfixture,0,10\nfixture,0,20\nfixture,0,30\nfixture,1,40\nfixture,1,50");
    }
}
