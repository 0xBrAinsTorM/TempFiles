out="test_50mb.jpg"
printf '\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x02\x00\x00\x01\x00\x01\x00\x00' > "${out}.tmp"
header_len=$(wc -c < "${out}.tmp")
target=$((50 * 1024 * 1024))
pad=$((target - header_len - 2))
dd if=/dev/zero bs=1 count=$pad status=none >> "${out}.tmp"
printf '\xFF\xD9' >> "${out}.tmp"
mv "${out}.tmp" "${out}"
ls -lh "${out}"
