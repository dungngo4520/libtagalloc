const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const root_mod = b.createModule(.{
        .root_source_file = b.path("src/libtagalloc.zig"),
        .target = target,
        .optimize = optimize,
    });

    const lib = b.addLibrary(.{
        .name = "tagalloc",
        .root_module = root_mod,
        .linkage = .static,
    });

    // Install the header next to the .a for simpler consumption.
    b.installLibFile("include/libtagalloc.h", "libtagalloc.h");
    b.installArtifact(lib);

    const poolreader_mod = b.createModule(.{
        .root_source_file = b.path("src/poolreader.zig"),
        .target = target,
        .optimize = optimize,
    });
    const poolreader = b.addExecutable(.{
        .name = "tagalloc-poolreader",
        .root_module = poolreader_mod,
    });
    b.installArtifact(poolreader);

    const poolreader_step = b.step("poolreader", "Build tagalloc-poolreader");
    poolreader_step.dependOn(&poolreader.step);

    const demo_mod = b.createModule(.{
        .root_source_file = b.path("src/demo.zig"),
        .target = target,
        .optimize = optimize,
    });
    const demo = b.addExecutable(.{
        .name = "tagalloc-demo",
        .root_module = demo_mod,
    });
    b.installArtifact(demo);

    const demo_step = b.step("demo", "Build tagalloc-demo");
    demo_step.dependOn(&demo.step);

    const test_step = b.step("test", "Run library tests");

    const test_mod = b.createModule(.{
        .root_source_file = b.path("src/libtagalloc.zig"),
        .target = target,
        .optimize = optimize,
    });
    const unit_tests = b.addTest(.{ .root_module = test_mod });
    test_step.dependOn(&b.addRunArtifact(unit_tests).step);
}
