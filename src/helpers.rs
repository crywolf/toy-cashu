/// Finds a combination of values in a slice that sum up to a specific target value
pub fn find_subset_sum(slice: &[u64], target: u64) -> Option<Vec<u64>> {
    // Recursive helper function to find subset
    fn subset_sum_recursive(
        slice: &[u64],
        target: i128,
        current: &mut Vec<u64>,
    ) -> Option<Vec<u64>> {
        // Base cases
        if target == 0 {
            return Some(current.clone());
        }
        if target < 0 || slice.is_empty() {
            return None;
        }

        // Try including the first element
        current.push(slice[0]);
        if let Some(result) = subset_sum_recursive(&slice[1..], target - slice[0] as i128, current)
        {
            return Some(result);
        }
        current.pop(); // Backtrack

        // Try excluding the first element
        subset_sum_recursive(&slice[1..], target, current)
    }

    let mut current = Vec::new();
    subset_sum_recursive(slice, target as i128, &mut current)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_subset_sum() {
        let numbers = [128, 512, 256, 64, 32, 8, 2];

        assert_eq!(find_subset_sum(&numbers, 40), Some(vec![32, 8]));
        assert_eq!(find_subset_sum(&numbers, 256), Some(vec![256]));
        assert_eq!(find_subset_sum(&numbers, 7), None);
        assert_eq!(find_subset_sum(&numbers, 576), Some(vec![512, 64]));
        assert_eq!(find_subset_sum(&numbers, 577), None);
        assert_eq!(find_subset_sum(&numbers, 42), Some(vec![32, 8, 2]));
    }
}
