/// Finds a combination of values in a slice that sum up to a specific target value
pub fn find_subset_sum(slice: &[u64], target: u64) -> Option<Vec<u64>> {
    // Early exit for impossible cases
    if slice.is_empty() || target == 0 {
        return None;
    }

    // Use a bitset-like approach for tracking possible sums
    let mut dp = vec![false; (target + 1) as usize];
    dp[0] = true;

    // Track the elements used to reach each sum
    let mut path = vec![vec![]; (target + 1) as usize];

    // Iterate through all numbers in the slice
    for &num in slice {
        // Work backwards to avoid using the same element multiple times
        for j in (num as usize..=target as usize).rev() {
            if dp[j - num as usize] && !dp[j] {
                dp[j] = true;
                path[j] = path[j - num as usize].clone();
                path[j].push(num);
            }
        }
    }

    // Return the subset if the target sum is possible
    if dp[target as usize] {
        Some(path[target as usize].clone())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_subset_sum() {
        let numbers = [
            65536, 65536, 32768, 32768, 16384, 16384, 16384, 16384, 8192, 8192, 4096, 2048, 2048,
            1024, 1024, 1024, 1024, 1024, 512, 512, 512, 512, 512, 256, 256, 256, 128, 128, 64, 64,
            32, 32, 32, 16, 16, 16, 8, 1, 1,
        ];

        assert_eq!(find_subset_sum(&numbers, 40), Some(vec![32, 8]));
        assert_eq!(find_subset_sum(&numbers, 256), Some(vec![256]));
        assert_eq!(find_subset_sum(&numbers, 7), None);
        assert_eq!(find_subset_sum(&numbers, 576), Some(vec![512, 64]));
        assert_eq!(find_subset_sum(&numbers, 579), None);
        assert_eq!(find_subset_sum(&numbers, 42), Some(vec![32, 8, 1, 1]));
        assert_eq!(find_subset_sum(&numbers, 252502), None);

        assert_eq!(
            find_subset_sum(&numbers, 252504),
            Some(vec![
                65536, 65536, 32768, 32768, 16384, 16384, 16384, 4096, 2048, 512, 64, 16, 8
            ])
        );
    }
}
