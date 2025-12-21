const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const abi_mod = b.createModule(.{
        .root_source_file = b.path("src/abi.zig"),
        .target = target,
        .optimize = optimize,
    });

    const root_mod = b.createModule(.{
        .root_source_file = b.path("src/libtagalloc.zig"),
        .target = target,
        .optimize = optimize,
    });
    root_mod.addImport("abi", abi_mod);

    const tagalloc_lib = b.addLibrary(.{
        .name = "tagalloc",
        .root_module = root_mod,
        .linkage = .static,
    });

    // Install the header next to the .a for simpler consumption.
    b.installLibFile("include/libtagalloc.h", "libtagalloc.h");
    b.installArtifact(tagalloc_lib);

    const test_step = b.step("test", "Run tests");
    {
        const test_mod = b.createModule(.{
            .root_source_file = b.path("src/tests.zig"),
            .target = target,
            .optimize = optimize,
        });
        test_mod.addImport("abi", abi_mod);

        const poolreader_lib_mod = b.createModule(.{
            .root_source_file = b.path("tools/poolreader/lib.zig"),
            .target = target,
            .optimize = optimize,
        });
        poolreader_lib_mod.addImport("abi", abi_mod);
        test_mod.addImport("poolreader_lib", poolreader_lib_mod);

        const unit_tests = b.addTest(.{ .root_module = test_mod });
        test_step.dependOn(&b.addRunArtifact(unit_tests).step);
    }

    // Poolreader tool.
    const poolreader_step = b.step("poolreader", "Build poolreader");
    {
        const mod = b.createModule(.{
            .root_source_file = b.path("tools/poolreader/main.zig"),
            .target = target,
            .optimize = optimize,
        });
        mod.addImport("abi", abi_mod);
        const exe = b.addExecutable(.{ .name = "tagalloc-poolreader", .root_module = mod });
        poolreader_step.dependOn(&b.addInstallArtifact(exe, .{}).step);
    }

    // Demo programs.
    const demo_step = b.step("demo", "Build demos");
    {
        const demo_zig_mod = b.createModule(.{
            .root_source_file = b.path("examples/demo.zig"),
            .target = target,
            .optimize = optimize,
        });
        demo_zig_mod.addImport("tagalloc", root_mod);
        const demo_zig = b.addExecutable(.{ .name = "tagalloc-demo-zig", .root_module = demo_zig_mod });
        demo_step.dependOn(&b.addInstallArtifact(demo_zig, .{}).step);

        const quickstart_mod = b.createModule(.{
            .root_source_file = b.path("examples/quickstart.zig"),
            .target = target,
            .optimize = optimize,
        });
        quickstart_mod.addImport("tagalloc", root_mod);
        const quickstart = b.addExecutable(.{ .name = "tagalloc-quickstart", .root_module = quickstart_mod });
        demo_step.dependOn(&b.addInstallArtifact(quickstart, .{}).step);

        const demo_cpp_mod = b.createModule(.{
            .root_source_file = null,
            .target = target,
            .optimize = optimize,
        });
        const demo_cpp = b.addExecutable(.{ .name = "tagalloc-demo-cpp", .root_module = demo_cpp_mod });
        demo_cpp.addCSourceFile(.{ .file = b.path("examples/demo.cpp"), .flags = &.{"-std=c++17"}, .language = .cpp });
        demo_cpp.linkLibC();
        demo_cpp.linkLibCpp();
        demo_cpp.linkLibrary(tagalloc_lib);
        demo_step.dependOn(&b.addInstallArtifact(demo_cpp, .{}).step);
    }

    // Benchmarks.
    const bench_step = b.step("benchmark", "Build benchmarks");
    {
        const bench_slab_mod = b.createModule(.{
            .root_source_file = b.path("benchmark/bench_slab.zig"),
            .target = target,
            .optimize = optimize,
        });
        bench_slab_mod.addImport("tagalloc", root_mod);
        const bench_slab = b.addExecutable(.{ .name = "tagalloc-bench-slab", .root_module = bench_slab_mod });
        bench_step.dependOn(&b.addInstallArtifact(bench_slab, .{}).step);

        const stress_mod = b.createModule(.{
            .root_source_file = b.path("benchmark/stress.zig"),
            .target = target,
            .optimize = optimize,
        });
        stress_mod.addImport("tagalloc", root_mod);
        const stress = b.addExecutable(.{ .name = "tagalloc-stress", .root_module = stress_mod });
        bench_step.dependOn(&b.addInstallArtifact(stress, .{}).step);
    }
}
