import {
  Body,
  Controller,
  Get,
  HttpCode,
  Param,
  Post,
  Req,
  UseGuards,
} from "@nestjs/common";
import { ApiOperation, ApiSecurity, ApiTags } from "@nestjs/swagger";
import { ThrottlerGuard } from "@nestjs/throttler";
import { ApiKeyGuard } from "../guards/api-key.guard";
import { ApiKeyScopes } from "../decorators/api-key-scopes.decorator";
import { AdvisoriesService } from "./advisories.service";
import { AdvisoryQueryDto } from "./advisory-query.dto";

@ApiTags("External API — Advisories")
@ApiSecurity("api-key")
@Controller("v1/advisories")
@UseGuards(ApiKeyGuard, ThrottlerGuard)
@ApiKeyScopes("vulnerabilities:read")
export class AdvisoriesController {
  constructor(private readonly service: AdvisoriesService) {}

  @Get("capabilities")
  @ApiOperation({
    summary: "Advisory capabilities, ecosystems and batch limit",
  })
  capabilities() {
    return this.service.capabilities();
  }

  @Post("query")
  @HttpCode(200)
  @ApiOperation({
    summary:
      "Query public package versions, preserving input order and partial failures",
  })
  query(@Body() body: AdvisoryQueryDto, @Req() request: any) {
    return this.service.query(body.packages, request.apiKeyId);
  }

  @Get(":id")
  @ApiOperation({
    summary: "Resolve CVE, GHSA, PYSEC or GO advisory and public aliases",
  })
  get(@Param("id") id: string, @Req() request: any) {
    return this.service.getById(id, request.apiKeyId);
  }
}

@ApiTags("External API — Advisories")
@ApiSecurity("api-key")
@Controller("v1/vulnerabilities")
@UseGuards(ApiKeyGuard, ThrottlerGuard)
@ApiKeyScopes("vulnerabilities:read")
export class VulnerabilityAssessmentController {
  constructor(private readonly service: AdvisoriesService) {}

  @Get(":cveId/assessment")
  @ApiOperation({
    summary:
      "Advisory evidence for a CVE; application exploitability is decided by the caller",
  })
  assessment(@Param("cveId") id: string, @Req() request: any) {
    return this.service.getById(id, request.apiKeyId);
  }
}
