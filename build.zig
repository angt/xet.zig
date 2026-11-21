const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const test_filters = b.option([]const []const u8, "test-filter", "Run only tests matching a filter") orelse &.{};

    const xet = b.addModule("xet", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    const support = b.createModule(.{
        .root_source_file = b.path("tests/support.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "xet", .module = xet }},
    });

    const test_step = b.step("test", "Run the test suite");

    const core_module = b.createModule(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    const core_support = b.createModule(.{
        .root_source_file = b.path("tests/support.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "xet", .module = core_module }},
    });
    core_module.addImport("regression_support", core_support);
    const core_tests = b.addTest(.{
        .filters = test_filters,
        .root_module = core_module,
    });
    test_step.dependOn(&b.addRunArtifact(core_tests).step);

    const regression_tests = b.addTest(.{
        .filters = test_filters,
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/regression.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "xet", .module = xet },
                .{ .name = "regression_support", .module = support },
            },
        }),
    });
    test_step.dependOn(&b.addRunArtifact(regression_tests).step);
}
