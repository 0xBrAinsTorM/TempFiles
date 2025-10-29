out="test_50mb.pdf"
printf '%s\n' '%PDF-1.4' '%âãÏÓ' > "${out}.tmp"
header_len=$(wc -c < "${out}.tmp")
target=$((50 * 1024 * 1024))   # 50 MB
pad=$((target - header_len - 6))
dd if=/dev/zero bs=1 count=$pad status=none >> "${out}.tmp"
printf '%%EOF\n' >> "${out}.tmp"
mv "${out}.tmp" "${out}"
ls -lh "${out}"
