class Y509 < Formula
  desc "Certificate Chain TUI Viewer"
  homepage "https://github.com/kanywst/y509"
  url "https://github.com/kanywst/y509/archive/refs/tags/v0.1.0.tar.gz"
  sha256 "REPLACE_WITH_ACTUAL_SHA256_AFTER_RELEASE"
  license "MIT"
  head "https://github.com/kanywst/y509.git", branch: "main"

  depends_on "go" => :build

  def install
    system "go", "build", *std_go_args(ldflags: "-s -w -X github.com/kanywst/y509/internal/version.Version=#{version}")
    
    # Generate shell completions
    generate_completions_from_executable(bin/"y509", "completion")

    # Install man page if it exists
    man1.install "man/man1/y509.1" if File.exist? "man/man1/y509.1"
  end

  test do
    assert_match "y509 version #{version}", shell_output("#{bin}/y509 --version")
    assert_match "Certificate Chain TUI Viewer", shell_output("#{bin}/y509 --help")
  end
end
