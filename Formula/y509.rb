class Y509 < Formula
  desc "Certificate Chain TUI Viewer"
  homepage "https://github.com/kanywst/y509"
  url "https://github.com/kanywst/y509/archive/refs/tags/v0.2.0.tar.gz"
  sha256 "6964c28c35bc1efd5a695caec6624614e188b49b8dba411915c1a3c360aaa4ad"
  license "MIT"
  head "https://github.com/kanywst/y509.git", branch: "main"

  depends_on "go" => :build

  def install
    # Change to the "cmd/y509" directory, which is a common convention in Go projects
    # for organizing binaries. The "y509" binary is located in this subdirectory.
    cd "cmd/y509" do
      system "go", "build", *std_go_args(ldflags: "-s -w -X github.com/kanywst/y509/internal/version.Version=#{version}")
    end
    
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
