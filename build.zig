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
    xet.addImport("test_support", support);

    const unit_tests = b.addTest(.{
        .filters = test_filters,
        .root_module = xet,
    });
    const integration_tests = b.addTest(.{
        .filters = test_filters,
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/root.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "xet", .module = xet },
                .{ .name = "test_support", .module = support },
            },
        }),
    });

    const test_step = b.step("test", "Run the test suite");
    test_step.dependOn(&b.addRunArtifact(unit_tests).step);
    test_step.dependOn(&b.addRunArtifact(integration_tests).step);
}
