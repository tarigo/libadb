pub trait Checksumable {
    type Checksum;

    fn calculate_checksum(&self) -> Self::Checksum;
}
